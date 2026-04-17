"""
utils/packet_templates.py - TLS packet construction and parsing utilities.

Provides classes for building and parsing TLS handshake packets:
- ClientHelloMaker: Constructs fake TLS 1.3 ClientHello messages with a custom SNI,
  random bytes, session ID, and key share. Also can parse them back.
- ServerHelloMaker: Constructs and parses TLS ServerHello messages.

These are used to generate the fake ClientHello that is injected with the spoofed SNI
to fool DPI middleboxes.
"""

import struct


class ClientHelloMaker:
    """
    Builds and parses TLS 1.3 ClientHello messages.
    
    The template is based on a real ClientHello with specific cipher suites and extensions.
    Key customizable fields: random (32B), session_id (32B), SNI hostname, key_share (32B).
    Padding is added to maintain a fixed total packet size of 517 bytes.
    """
    # Hex-encoded template of a full TLS ClientHello packet
    tls_ch_template_str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    tls_ch_template = bytes.fromhex(tls_ch_template_str)
    template_sni = "mci.ir".encode()  # Placeholder SNI in the template
    # Static byte segments extracted from the template for reassembly:
    static1 = tls_ch_template[:11]                                         # TLS record header + handshake header + version
    static2 = b"\x20"                                                      # Session ID length (32 bytes)
    static3 = tls_ch_template[76:120]                                      # Cipher suites + compression methods
    static4 = tls_ch_template[127 + len(template_sni):262 + len(template_sni)]  # Extensions after SNI, before key_share
    static5 = b"\x00\x15"                                                  # Padding extension type ID
    # TLS ChangeCipherSpec message (signals transition to encrypted communication)
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    # TLS Application Data record header (content type 0x17, TLS 1.2 version)
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes,
                              key_share: bytes) -> bytes:
        """
        Build a complete TLS ClientHello packet with custom fields.
        Args:
            rnd: 32 random bytes for the ClientHello.random field
            sess_id: 32 bytes for the session ID
            target_sni: the SNI hostname to embed (this is the spoofed domain)
            key_share: 32 bytes for the key_share extension
        Returns: Complete TLS ClientHello as bytes (517 bytes total)
        """
        # Build the SNI extension: extension_type(2) + lengths + hostname
        server_name_ext = struct.pack("!H", len(target_sni) + 5) + struct.pack("!H",
                                                                               len(target_sni) + 3) + b"\x00" + struct.pack(
            "!H", len(target_sni)) + target_sni
        # Padding extension to fill remaining space and keep packet size constant
        padding_ext = struct.pack("!H", 219 - len(target_sni)) + (b"\x00" * (219 - len(target_sni)))
        # Assemble all static and dynamic parts into the final ClientHello
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + server_name_ext + cls.static4 + key_share + cls.static5 + padding_ext
        # Field positions: rnd->[11:43)  sess_id->[44:76)  key_share->[262+len(sni):294+len(sni))

    @classmethod
    def parse_client_hello(cls, client_hello_bytes: bytes):
        """
        Parse a 517-byte ClientHello back into its components.
        Returns: (random, session_id, sni_hostname, key_share)
        Asserts that reassembling the parsed fields produces the original bytes.
        """
        if len(client_hello_bytes) != 517:
            raise ValueError(f"Expected 517-byte ClientHello, got {len(client_hello_bytes)} bytes")
        rnd = client_hello_bytes[11:43]       # 32-byte random
        sess_id = client_hello_bytes[44:76]    # 32-byte session ID
        # Extract SNI: read length at offset 125-127, then read that many bytes
        sni_len = struct.unpack("!H", client_hello_bytes[125:127])[0]
        tls_sni = client_hello_bytes[127:127 + sni_len]
        ks_ind = 262 + len(tls_sni)            # Key share offset depends on SNI length
        key_share = client_hello_bytes[ks_ind:ks_ind + 32]
        if cls.get_client_hello_with(rnd, sess_id, tls_sni, key_share) != client_hello_bytes:
            raise ValueError("ClientHello round-trip check failed: parsed fields do not reassemble to original bytes")
        return rnd, sess_id, tls_sni.decode(), key_share

    @classmethod
    def get_client_response_with(cls, app_data1: bytes):
        """Build a TLS client response: ChangeCipherSpec + Application Data record."""
        return cls.tls_change_cipher + cls.tls_app_data_header + struct.pack("!H", len(app_data1)) + app_data1

    @classmethod
    def parse_client_response(cls, client_response_bytes: bytes):
        """Parse a TLS client response to extract the application data payload."""
        if len(client_response_bytes) < 32:
            raise ValueError(f"Expected at least 32-byte client response, got {len(client_response_bytes)} bytes")
        app_data1 = client_response_bytes[11:]
        if cls.get_client_response_with(app_data1) != client_response_bytes:
            raise ValueError("ClientResponse round-trip check failed: parsed fields do not reassemble to original bytes")
        return app_data1


class ServerHelloMaker:
    """
    Builds and parses TLS 1.3 ServerHello messages.
    Similar structure to ClientHelloMaker but for the server side of the handshake.
    """
    # Hex-encoded template of a full TLS ServerHello packet
    tls_sh_template_str = "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e"
    tls_sh_template = bytes.fromhex(tls_sh_template_str)
    # Static segments extracted from the ServerHello template
    static1 = tls_sh_template[:11]               # TLS record header + handshake header + version
    static2 = b"\x20"                             # Session ID length (32 bytes)
    static3 = tls_sh_template[76:95]             # Cipher suite + extensions before key_share
    # TLS ChangeCipherSpec and Application Data headers (same as ClientHello)
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_server_hello_with(cls, rnd: bytes, sess_id: bytes, key_share: bytes, app_data1: bytes):
        """Build a complete TLS ServerHello + ChangeCipherSpec + Application Data response."""
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + key_share + cls.tls_change_cipher + cls.tls_app_data_header + struct.pack(
            "!H", len(app_data1)) + app_data1

    @classmethod
    def parse_server_hello(cls, server_hello_bytes: bytes):
        """
        Parse a ServerHello message (min 159 bytes) into its components.
        Returns: (random, session_id, key_share, app_data)
        Asserts that reassembling the parsed fields produces the original bytes.
        """
        if len(server_hello_bytes) < 159:
            raise ValueError(f"Expected at least 159-byte ServerHello, got {len(server_hello_bytes)} bytes")
        rnd = server_hello_bytes[11:43]           # 32-byte server random
        sess_id = server_hello_bytes[44:76]       # 32-byte session ID
        key_share = server_hello_bytes[95:127]    # 32-byte key share
        app_data1 = server_hello_bytes[138:]      # Remaining bytes are application data
        if cls.get_server_hello_with(rnd, sess_id, key_share, app_data1) != server_hello_bytes:
            raise ValueError("ServerHello round-trip check failed: parsed fields do not reassemble to original bytes")
        return rnd, sess_id, key_share, app_data1
