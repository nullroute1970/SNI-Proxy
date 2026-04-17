"""
utils/network_tools.py - Network interface detection utilities.

Provides functions to auto-detect the local machine's default network interface
IP addresses (IPv4 and IPv6) by creating a temporary UDP socket and checking
which local address the OS selects for routing to a given destination.
"""

import socket


def get_default_interface_ipv4(addr="8.8.8.8") -> str:
    """
    Detect the default IPv4 interface address used to reach 'addr'.
    Creates a UDP socket and connects to the target (no actual data is sent),
    then reads the local address the OS bound the socket to.
    Returns an empty string if no route is available.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))  # Connect to DNS port (no data sent for UDP)
    except OSError:
        return ""
    else:
        return s.getsockname()[0]  # Return the local IP address
    finally:
        s.close()


def get_default_interface_ipv6(addr="2001:4860:4860::8888") -> str:
    """
    Detect the default IPv6 interface address used to reach 'addr'.
    Same technique as IPv4 — uses a temporary UDP socket.
    Returns an empty string if no IPv6 route is available.
    """
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))  # Connect to DNS port (no data sent for UDP)
    except OSError:
        return ""
    else:
        return s.getsockname()[0]  # Return the local IPv6 address
    finally:
        s.close()
