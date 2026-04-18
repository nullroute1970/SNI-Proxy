"""
injecter.py - Abstract base class for TCP packet injection using WinDivert.

Provides TcpInjector, which opens a WinDivert handle with a given filter,
captures matching TCP packets in a loop, and delegates processing to the
abstract inject() method. Subclasses (e.g. FakeTcpInjector) implement
inject() to inspect, modify, or re-inject packets.
"""

from abc import ABC, abstractmethod
import logging

from pydivert import WinDivert, Packet

logger = logging.getLogger(__name__)


class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        self.w: WinDivert = WinDivert(w_filter)
        self._stopped = False

    @abstractmethod
    def inject(self, packet: Packet):
        """Process a captured packet. Must be implemented by subclasses."""
        raise NotImplementedError

    def stop(self):
        """Signal the run() loop to stop and close the WinDivert handle."""
        self._stopped = True
        try:
            self.w.close()
        except Exception:
            pass

    def run(self):
        """Main capture loop: receives packets from WinDivert and passes them to inject()."""
        self.w.open()
        try:
            while True:
                try:
                    packet = self.w.recv(65575)  # Receive one packet (max 65575 bytes)
                    if self._stopped:
                        break
                    self.inject(packet)
                except Exception:
                    if self._stopped:
                        logger.debug("WinDivert injector stopped cleanly.")
                        break
                    logger.exception("Error processing packet in injector loop")
        finally:
            try:
                self.w.close()
            except (RuntimeError, OSError):
                pass  # Already closed by stop()
