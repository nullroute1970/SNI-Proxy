"""
fake_tcp.py - Fake TCP injection logic for SNI spoofing.

This module provides:
- FakeInjectiveConnection: Extends MonitorConnection with state needed for
  injecting a fake TLS ClientHello during the TCP handshake.
- FakeTcpInjector: Extends TcpInjector to intercept live TCP packets via
  WinDivert, monitor the 3-way handshake, and inject a fake ClientHello
  with a deliberately wrong TCP sequence number right after the handshake
  completes. This tricks DPI middleboxes into seeing the allowed SNI while
  the real server discards the out-of-sequence fake packet.
"""

import asyncio
import logging
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from pydivert import Packet

# Shared thread pool for fake packet injection — reusing threads avoids per-connection
# OS thread creation/destruction overhead. Replaced when a new injector is constructed.
_INJECTION_POOL: ThreadPoolExecutor | None = None

from monitor_connection import MonitorConnection
from injecter import TcpInjector
from metrics import metrics

logger = logging.getLogger(__name__)


class FakeInjectiveConnection(MonitorConnection):
    """
    Represents a single outgoing connection that needs fake data injection.
    Extends MonitorConnection with:
    - fake_data: the fake TLS ClientHello bytes to inject
    - sch_fake_sent / fake_sent: flags tracking injection state
    - t2a_event / t2a_msg: asyncio Event for thread-to-async communication
      (the injector thread signals the async handle() when bypass is done)
    - bypass_method: which DPI evasion technique to use
    - peer_sock: the incoming client socket (closed on error)
    """
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str, peer_sock: socket.socket,
                 fake_ttl: int = 1, ip_frag_offset: int = 8, urgent_pointer_size: int = 3,
                 fake_inject_delay: float = 0.001):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data           # The fake ClientHello payload to inject
        self.sch_fake_sent = False           # True once fake send has been scheduled
        self.fake_sent = False               # True once fake packet was actually sent
        self.t2a_event = asyncio.Event()     # Thread-to-async event for signaling completion
        self.t2a_msg = ""                    # Message from injector thread: "fake_data_ack_recv" or "unexpected_close"
        self.bypass_method = bypass_method   # DPI bypass method (e.g. "wrong_seq")
        self.peer_sock = peer_sock           # The local/incoming client socket
        self.fake_ttl = fake_ttl             # TTL value for low_ttl bypass method
        self.ip_frag_offset = ip_frag_offset # Bytes in first IP fragment for ip_fragmentation
        self.urgent_pointer_size = urgent_pointer_size  # Bytes of urgent data for tcp_urgent_pointer
        self.fake_inject_delay = fake_inject_delay  # Seconds to delay before injecting fake packet
        self.running_loop = asyncio.get_running_loop()  # Reference to the asyncio loop for thread-safe signaling
        self.bypass_counted = False  # Whether this connection's bypass result has been counted in metrics


class FakeTcpInjector(TcpInjector):
    """
    Packet-level TCP injector that intercepts the 3-way handshake via WinDivert
    and injects a fake TLS ClientHello immediately after the handshake completes.
    
    Workflow:
    1. Captures outbound SYN -> records seq number
    2. Captures inbound SYN-ACK -> records server seq, validates ack
    3. Captures outbound ACK (handshake complete) -> schedules fake data injection
    4. Sends fake ClientHello with wrong seq number (so server ignores it, DPI sees it)
    5. Captures inbound ACK for the real handshake -> signals async code that bypass succeeded
    """

    def __init__(self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection],
                 connections_lock: threading.Lock, pool_size: int = 32):
        super().__init__(w_filter)
        self.connections = connections  # Shared dict of active connections to monitor
        self.connections_lock = connections_lock  # Lock for thread-safe dict access
        # Replace the module-level pool with a fresh one sized per config
        global _INJECTION_POOL
        if _INJECTION_POOL is not None:
            _INJECTION_POOL.shutdown(wait=False, cancel_futures=False)
        _INJECTION_POOL = ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="sni_inject")
        # Build once per injector instance — avoids rebuilding on every bypass call
        self._bypass_handlers = {
            "wrong_seq": self._send_wrong_seq,
            "wrong_checksum": self._send_wrong_checksum,
            "low_ttl": self._send_low_ttl,
            "ip_fragmentation": self._send_ip_fragmentation,
            "fake_rst": self._send_fake_rst,
            "tcp_urgent_pointer": self._send_tcp_urgent_pointer,
        }

    @staticmethod
    def _ip_checksum(header_bytes: bytes) -> int:
        """Calculate the IP header checksum (RFC 1071)."""
        if len(header_bytes) % 2 == 1:
            header_bytes += b'\x00'
        s = 0
        for i in range(0, len(header_bytes), 2):
            s += (header_bytes[i] << 8) + header_bytes[i + 1]
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        """
        Runs in a separate thread to inject the fake ClientHello packet.
        A small delay (1ms) ensures the real ACK is sent first.
        The packet is modified to carry the fake payload with a wrong sequence number
        so the server discards it, but DPI middleboxes see the spoofed SNI.
        """
        try:
            self._fake_send_thread_inner(packet, connection)
        except Exception:
            logger.warning("Error in fake_send_thread for %s:%s -> %s:%s, closing connection",
                           connection.src_ip, connection.src_port,
                           connection.dst_ip, connection.dst_port,
                           exc_info=True)
            with connection.thread_lock:
                try:
                    connection.sock.close()
                except OSError:
                    pass
                try:
                    connection.peer_sock.close()
                except OSError:
                    pass
                connection.monitor = False
                connection.t2a_msg = "unexpected_close"
                try:
                    connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
                except RuntimeError:
                    logger.debug("Event loop closed; could not signal t2a_event for %s:%s",
                                 connection.src_ip, connection.src_port)

    def _send_wrong_seq(self, packet: Packet, connection: FakeInjectiveConnection):
        """Inject fake ClientHello with a deliberately wrong TCP sequence number."""
        packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
        connection.fake_sent = True
        self.w.send(packet, True)

    def _send_wrong_checksum(self, packet: Packet, connection: FakeInjectiveConnection):
        """Inject fake ClientHello with correct seq but invalid TCP checksum."""
        packet.tcp.seq_num = (connection.syn_seq + 1) & 0xffffffff
        connection.fake_sent = True
        self.w.send(packet, False)

    def _send_low_ttl(self, packet: Packet, connection: FakeInjectiveConnection):
        """Inject fake ClientHello with a low IP TTL so it expires before the server."""
        packet.tcp.seq_num = (connection.syn_seq + 1) & 0xffffffff
        if packet.ipv4:
            packet.ipv4.ttl = connection.fake_ttl
        connection.fake_sent = True
        self.w.send(packet, True)

    def _send_ip_fragmentation(self, packet: Packet, connection: FakeInjectiveConnection):
        """Send fake ClientHello as two IP fragments spanning the SNI field."""
        packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
        if packet.ipv4:
            packet.ipv4.df = False
        packet.recalculate_checksums()
        raw_bytes = bytearray(packet.raw)
        ip_hdr_len = (raw_bytes[0] & 0x0F) * 4
        ip_payload = raw_bytes[ip_hdr_len:]
        total_ip_payload_len = len(ip_payload)

        frag_offset_bytes = connection.ip_frag_offset
        frag_offset_bytes = max(8, (frag_offset_bytes // 8) * 8)
        if frag_offset_bytes >= total_ip_payload_len:
            frag_offset_bytes = max(8, (total_ip_payload_len // 2 // 8) * 8)

        # Fragment 1: IP header + first N bytes, MF=1, frag_offset=0
        frag1_payload = ip_payload[:frag_offset_bytes]
        frag1 = bytearray(raw_bytes[:ip_hdr_len]) + frag1_payload
        frag1_total = ip_hdr_len + len(frag1_payload)
        struct.pack_into("!H", frag1, 2, frag1_total)
        struct.pack_into("!H", frag1, 6, 0x2000)  # MF=1, offset=0
        struct.pack_into("!H", frag1, 10, 0)
        ip_cksum = self._ip_checksum(bytes(frag1[:ip_hdr_len]))
        struct.pack_into("!H", frag1, 10, ip_cksum)

        # Fragment 2: IP header + remaining bytes, MF=0, frag_offset=N/8
        frag2_payload = ip_payload[frag_offset_bytes:]
        frag2 = bytearray(raw_bytes[:ip_hdr_len]) + frag2_payload
        frag2_total = ip_hdr_len + len(frag2_payload)
        struct.pack_into("!H", frag2, 2, frag2_total)
        offset_units = frag_offset_bytes // 8
        struct.pack_into("!H", frag2, 6, offset_units & 0x1FFF)  # MF=0
        struct.pack_into("!H", frag2, 10, 0)
        ip_cksum2 = self._ip_checksum(bytes(frag2[:ip_hdr_len]))
        struct.pack_into("!H", frag2, 10, ip_cksum2)

        frag1_pkt = Packet(bytes(frag1), interface=packet.interface, direction=packet.direction)
        frag2_pkt = Packet(bytes(frag2), interface=packet.interface, direction=packet.direction)
        connection.fake_sent = True
        self.w.send(frag1_pkt, False)
        self.w.send(frag2_pkt, False)

    def _send_fake_rst(self, packet: Packet, connection: FakeInjectiveConnection):
        """Send a fake RST to trick DPI into dropping connection tracking state."""
        packet.tcp.psh = False
        packet.tcp.rst = True
        packet.tcp.ack = False
        packet.tcp.seq_num = (connection.syn_seq + 1 - 1) & 0xffffffff
        packet.ip.packet_len = packet.ip.packet_len - len(packet.tcp.payload)
        packet.tcp.payload = b""
        connection.fake_sent = True
        self.w.send(packet, True)
        connection.monitor = False
        connection.t2a_msg = "fake_data_ack_recv"
        try:
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        except RuntimeError:
            logger.debug("Event loop closed; could not signal t2a_event for %s:%s",
                         connection.src_ip, connection.src_port)

    def _send_tcp_urgent_pointer(self, packet: Packet, connection: FakeInjectiveConnection):
        """Send fake ClientHello with URG flag and urgent pointer to desync DPI."""
        packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
        packet.tcp.urg = True
        packet.tcp.urg_ptr = connection.urgent_pointer_size
        connection.fake_sent = True
        self.w.send(packet, True)

    def _fake_send_thread_inner(self, packet: Packet, connection: FakeInjectiveConnection):
        """Inner logic for fake_send_thread, separated for error handling."""
        time.sleep(connection.fake_inject_delay)
        with connection.thread_lock:
            if not connection.monitor:
                return

            # Common setup: set PSH flag and attach the fake ClientHello as TCP payload
            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff

            handler = self._bypass_handlers.get(connection.bypass_method)
            if handler:
                handler(packet, connection)
            else:
                logger.error("Unimplemented bypass method: %s", connection.bypass_method)

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        """
        Handles unexpected packets during the monitored handshake.
        Closes both sockets, signals the async handler that the connection failed,
        and forwards the packet without modification.
        """
        logger.warning("%s %s", info_m, packet)
        connection.sock.close()
        connection.peer_sock.close()
        connection.monitor = False
        if not connection.bypass_counted:
            connection.bypass_counted = True
            metrics.bypass_failed()
        connection.t2a_msg = "unexpected_close"  # Notify async handler of failure
        try:
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        except RuntimeError:
            logger.debug("Event loop closed; could not signal t2a_event for %s:%s",
                         connection.src_ip, connection.src_port)
        self.w.send(packet, False)  # Forward the packet unmodified

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        """
        Processes inbound (server -> client) packets during the monitored handshake.
        Expected sequence:
        1. SYN-ACK from server: validates ack matches our SYN seq+1, records server seq.
        2. ACK after fake was sent: confirms the server acknowledged the real handshake
           (ignoring the fake packet), signals success to the async handler.
        """
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
            return
        # --- RST from server: connection rejected, close and signal failure ---
        if packet.tcp.rst:
            self.on_unexpected_packet(packet, connection, "RST from server:")
            return
        # --- SYN-ACK from server: validate and record server's sequence number ---
        if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound syn-ack packet, seq change! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound syn-ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(connection.syn_seq))
                return
            connection.syn_ack_seq = seq_num
            self.w.send(packet, False)
            return
        # --- Pure ACK after fake data was sent: server acknowledges the real handshake ---
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (
                not packet.tcp.fin) and (len(packet.tcp.payload) == 0) and connection.sch_fake_sent:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound ack packet, seq not matched! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound ack packet, ack not matched! " + str(ack_num) + " " + str(
                                              connection.syn_seq))
                return

            # Bypass succeeded: server ACK'd the real handshake, fake packet was ignored
            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"  # Signal success to async handler
            try:
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            except RuntimeError:
                logger.debug("Event loop closed; could not signal t2a_event for %s:%s",
                             connection.src_ip, connection.src_port)
            self.w.send(packet, False)  # Forward ACK to the OS TCP stack
            return
        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")
        return

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        """
        Processes outbound (client -> server) packets during the monitored handshake.
        Expected sequence:
        1. SYN: records our initial sequence number.
        2. ACK (completing 3-way handshake): forwards it and immediately schedules
           the fake ClientHello injection in a separate thread.
        """
        if connection.sch_fake_sent:
            # Pure ACKs with no payload are benign OS-generated window updates / keep-alives.
            # Forward them unmodified rather than treating them as a fatal handshake error.
            if (packet.tcp.ack and not packet.tcp.syn and not packet.tcp.rst
                    and not packet.tcp.fin and len(packet.tcp.payload) == 0):
                self.w.send(packet, False)
                return
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet, recv packet after fake sent!")
            return
        # --- SYN packet: record our initial sequence number ---
        if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, ack_num is not zero!")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, seq not matched! " + str(
                    seq_num) + " " + str(connection.syn_seq))
                return
            connection.syn_seq = seq_num  # Record our SYN sequence number
            self.w.send(packet, False)     # Forward SYN unmodified

            # --- duplicate_syn: send a second SYN carrying the fake ClientHello ---
            if connection.bypass_method == "duplicate_syn":
                packet.tcp.psh = True
                packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
                packet.tcp.payload = connection.fake_data
                if packet.ipv4:
                    packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff
                connection.fake_sent = True
                self.w.send(packet, True)  # Recalculate checksums

            return
        # --- ACK packet (completing the 3-way handshake): validate and trigger fake injection ---
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected outbound ack packet, seq not matched! " + str(
                                              seq_num) + " " + str(
                                              connection.syn_seq))
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected outbound ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(
                                              connection.syn_ack_seq))
                return

            self.w.send(packet, False)  # Forward the real ACK first
            connection.sch_fake_sent = True  # Mark that fake injection is scheduled

            # For duplicate_syn, the fake was already sent during SYN — no thread needed
            if connection.bypass_method != "duplicate_syn":
                # Submit to shared pool — avoids creating a new OS thread per connection
                _INJECTION_POOL.submit(self.fake_send_thread, packet, connection)
            return
        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")
        return

    def inject(self, packet: Packet):
        """
        Main packet dispatch method called by the WinDivert capture loop.
        Routes each captured packet to the appropriate handler based on direction.
        Packets for connections not being monitored are forwarded unmodified.
        """
        if packet.is_inbound:
            c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
            with self.connections_lock:
                connection = self.connections.get(c_id)
            if connection is None:
                self.w.send(packet, False)
                return
            with connection.thread_lock:
                if not connection.monitor:
                    self.w.send(packet, False)
                    return
                try:
                    self.on_inbound_packet(packet, connection)
                except Exception:
                    logger.warning("Error handling inbound packet for %s, closing connection",
                                   c_id, exc_info=True)
                    self.on_unexpected_packet(packet, connection, "exception during inbound handling:")
        elif packet.is_outbound:
            c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
            with self.connections_lock:
                connection = self.connections.get(c_id)
            if connection is None:
                self.w.send(packet, False)
                return
            with connection.thread_lock:
                if not connection.monitor:
                    self.w.send(packet, False)
                    return
                try:
                    self.on_outbound_packet(packet, connection)
                except Exception:
                    logger.warning("Error handling outbound packet for %s, closing connection",
                                   c_id, exc_info=True)
                    self.on_unexpected_packet(packet, connection, "exception during outbound handling:")
        else:
            logger.error("Unexpected packet direction: %s", packet)
            self.w.send(packet, False)
