"""
monitor_connection.py - Base class for tracking a TCP connection's state.

MonitorConnection holds the essential state for monitoring a single TCP connection:
- Source/destination IP and port
- SYN and SYN-ACK sequence numbers (for handshake tracking)
- A thread lock for safe concurrent access from the async loop and injector thread
- A monitor flag to enable/disable packet interception
"""

import socket
import threading


class MonitorConnection:
    """
    Tracks the state of a single TCP connection being monitored for packet injection.
    Used as a base class by FakeInjectiveConnection.
    """
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port):
        self.monitor = True          # Whether this connection is actively being monitored
        self.syn_seq = -1            # Our SYN sequence number (-1 = not yet seen)
        self.syn_ack_seq = -1        # Server's SYN-ACK sequence number (-1 = not yet seen)
        self.src_ip = src_ip         # Local/source IP address
        self.dst_ip = dst_ip         # Remote/destination IP address
        self.src_port = src_port     # Local/source port
        self.dst_port = dst_port     # Remote/destination port
        self.id = (self.src_ip, self.src_port, self.dst_ip, self.dst_port)  # Unique connection identifier tuple
        self.thread_lock = threading.Lock()  # Lock for thread-safe access from injector and async code
        self.sock = sock             # The actual socket object for this connection
