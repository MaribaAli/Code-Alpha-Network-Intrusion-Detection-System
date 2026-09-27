"""
packet_capture.py
Real, live packet capture using Scapy. Runs in a background thread so the
GUI never freezes. Uses short repeated sniff() calls (with a timeout) instead
of one long blocking sniff() call, so Stop Monitoring takes effect quickly
even when there is little or no traffic.

No fake/sample packets are ever generated here - every packet handed to the
callback comes directly from a live capture of real traffic on the selected
network interface.
"""

import threading
import time


class PacketCaptureError(Exception):
    pass


class PacketCapture:
    def __init__(self, callback, on_error=None):
        """
        callback: function(packet_info: dict) called for every captured
                  packet that has an IP layer. Called from the capture
                  thread - must be thread-safe (e.g. only queue.put()).
        on_error: function(message: str) called if capture fails. Also
                  called from the capture thread.
        """
        self.callback = callback
        self.on_error = on_error
        self._stop_event = threading.Event()
        self._thread = None
        self.running = False
        self.interface = None

    def list_interfaces(self):
        from src.utils import get_friendly_interfaces
        return get_friendly_interfaces()

    def start(self, interface=None):
        """Start capturing on the given interface (or the default one if None)."""
        if self.running:
            return
        self.interface = interface
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.running = True
        self._thread.start()

    def stop(self, timeout=3):
        """Signal the capture thread to stop and wait briefly for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self.running = False

    # ------------------------------------------------------------------ #

    def _capture_loop(self):
        try:
            from scapy.all import sniff
        except Exception as e:
            self._fail(
                "Scapy is not installed or could not be imported. "
                f"Run 'pip install scapy' inside your virtual environment. Details: {e}"
            )
            return

        while not self._stop_event.is_set():
            try:
                # timeout=1 means sniff() returns roughly every second even
                # with zero traffic, so the stop event is checked promptly.
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    timeout=1,
                )
            except PermissionError:
                self._fail(
                    "Permission denied while opening the network interface. "
                    "Close this app and re-run VS Code / the terminal as Administrator."
                )
                return
            except OSError as e:
                msg = str(e).lower()
                if "npcap" in msg or "winpcap" in msg or "no such device" in msg or "libpcap" in msg:
                    self._fail(
                        "No packet capture driver was found. Install Npcap from "
                        "https://npcap.com/#download (check 'WinPcap API-compatible mode' "
                        "during install), then restart this application."
                    )
                else:
                    self._fail(f"Network capture error: {e}")
                return
            except Exception as e:
                self._fail(f"Unexpected capture error: {e}")
                return

        self.running = False

    def _fail(self, message):
        self.running = False
        if self.on_error:
            self.on_error(message)

    def _process_packet(self, pkt):
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
        except Exception:
            return

        try:
            if IP not in pkt:
                return

            ip_layer = pkt[IP]
            info = {
                "timestamp": time.time(),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "length": len(pkt),
                "protocol": "OTHER",
                "src_port": None,
                "dst_port": None,
                "tcp_flags": None,
            }

            if TCP in pkt:
                info["protocol"] = "TCP"
                info["src_port"] = int(pkt[TCP].sport)
                info["dst_port"] = int(pkt[TCP].dport)
                info["tcp_flags"] = str(pkt[TCP].flags)
            elif UDP in pkt:
                info["protocol"] = "UDP"
                info["src_port"] = int(pkt[UDP].sport)
                info["dst_port"] = int(pkt[UDP].dport)
            elif ICMP in pkt:
                info["protocol"] = "ICMP"
                info["icmp_type"] = int(pkt[ICMP].type)

            if self.callback:
                self.callback(info)
        except Exception as e:
            if self.on_error:
                self.on_error(f"Error while parsing a captured packet: {e}")
