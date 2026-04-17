"""
metrics.py - Thread-safe connection metrics for the SNI Spoofing proxy.

Tracks active connections, successful bypasses, failures, and bytes relayed.
Uses threading.Lock for safe access from both the asyncio event loop and the
WinDivert injector thread.
"""

import threading
import time


class ConnectionMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._active_connections = 0
        self._total_connections = 0
        self._successful_bypasses = 0
        self._failed_bypasses = 0
        self._bytes_relayed = 0
        self._connect_failed = 0
        self._relay_broken = 0
        self._start_time = time.monotonic()

    def connection_started(self):
        with self._lock:
            self._active_connections += 1
            self._total_connections += 1

    def connection_ended(self):
        with self._lock:
            self._active_connections = max(0, self._active_connections - 1)

    def bypass_succeeded(self):
        with self._lock:
            self._successful_bypasses += 1

    def bypass_failed(self):
        with self._lock:
            self._failed_bypasses += 1

    def bytes_transferred(self, count: int):
        with self._lock:
            self._bytes_relayed += count

    def connect_failed(self):
        """Outgoing TCP connection to the target server could not be established."""
        with self._lock:
            self._connect_failed += 1

    def relay_broken(self):
        """An active relay was interrupted by a connection reset or network error."""
        with self._lock:
            self._relay_broken += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "active_connections": self._active_connections,
                "total_connections": self._total_connections,
                "successful_bypasses": self._successful_bypasses,
                "failed_bypasses": self._failed_bypasses,
                "bytes_relayed": self._bytes_relayed,
                "connect_failed": self._connect_failed,
                "relay_broken": self._relay_broken,
                "uptime_seconds": time.monotonic() - self._start_time,
            }


# Module-level singleton instance
metrics = ConnectionMetrics()
