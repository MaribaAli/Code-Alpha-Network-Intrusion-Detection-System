"""
intrusion_detector.py
Rule-based intrusion detection logic. Pure, testable logic with no GUI or
capture dependencies: it takes a packet_info dict (as produced by
PacketCapture) and returns a list of alert dicts.

All time-window math uses the timestamp carried on the packet itself
(pkt['timestamp']), not wall-clock time.time() calls inside this module -
this makes the detector fully unit-testable with synthetic timestamps.

Detections implemented:
 - Port scan            (many distinct destination ports from one source)
 - ICMP flood           (too many ICMP packets from one source)
 - TCP SYN flood        (too many bare SYN packets from one source)
 - High packet rate     (too many packets overall from one source)
 - Suspicious port      (a single connection attempt to a known-risky port)
 - Repeated connections (many connection attempts to the same destination)
"""

import time
from collections import defaultdict, deque


class IntrusionDetector:
    def __init__(self, config):
        self.config = config
        self.trusted_ips = set(config.get("trusted_ips", []) or [])

        # src_ip -> deque[(timestamp, dst_port)]
        self.port_scan_window = defaultdict(deque)
        # src_ip -> deque[timestamp]
        self.icmp_window = defaultdict(deque)
        # src_ip -> deque[timestamp]  (bare SYN packets)
        self.syn_window = defaultdict(deque)
        # src_ip -> deque[timestamp]  (all packets, for rate detection)
        self.rate_window = defaultdict(deque)
        # (src_ip, dst_ip) -> deque[timestamp] (SYN connection attempts)
        self.conn_window = defaultdict(deque)

    # ------------------------------------------------------------------ #

    def process_packet(self, pkt):
        """Feed one packet_info dict through every detection rule."""
        alerts = []
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        now = pkt.get("timestamp", time.time())

        if not src:
            return alerts

        # Trusted sources (e.g. your own router/DNS) are still shown in the
        # packet table by the GUI, but never generate detection alerts.
        if src in self.trusted_ips:
            return alerts

        cfg = self.config

        # --- High packet rate (per source) ---------------------------- #
        rate_cfg = cfg["high_packet_rate"]
        dq = self.rate_window[src]
        dq.append(now)
        self._trim(dq, now, rate_cfg["time_window_seconds"])
        if len(dq) >= rate_cfg["packet_threshold"]:
            alerts.append(self._make_alert(
                now, "High Packet Rate", src, dst, "Medium",
                f"{len(dq)} packets from {src} within {rate_cfg['time_window_seconds']}s "
                f"(threshold {rate_cfg['packet_threshold']})."
            ))

        # --- Port scan (many distinct destination ports) -------------- #
        dst_port = pkt.get("dst_port")
        if dst_port is not None:
            ps_cfg = cfg["port_scan"]
            dq2 = self.port_scan_window[src]
            dq2.append((now, dst_port))
            while dq2 and now - dq2[0][0] > ps_cfg["time_window_seconds"]:
                dq2.popleft()
            unique_ports = {p for _, p in dq2}
            if len(unique_ports) >= ps_cfg["port_threshold"]:
                alerts.append(self._make_alert(
                    now, "Port Scan", src, dst, "High",
                    f"{src} probed {len(unique_ports)} distinct destination ports "
                    f"within {ps_cfg['time_window_seconds']}s "
                    f"(threshold {ps_cfg['port_threshold']})."
                ))

            # --- Suspicious destination port (single-shot) ------------ #
            suspicious_ports = cfg.get("suspicious_ports", [])
            if dst_port in suspicious_ports:
                alerts.append(self._make_alert(
                    now, "Suspicious Port Access", src, dst, "Medium",
                    f"Connection attempt from {src} to {dst} on commonly-abused "
                    f"port {dst_port}."
                ))

        # --- ICMP flood ------------------------------------------------ #
        if pkt.get("protocol") == "ICMP":
            icmp_cfg = cfg["icmp_flood"]
            dq3 = self.icmp_window[src]
            dq3.append(now)
            self._trim(dq3, now, icmp_cfg["time_window_seconds"])
            if len(dq3) >= icmp_cfg["packet_threshold"]:
                alerts.append(self._make_alert(
                    now, "ICMP Flood", src, dst, "Critical",
                    f"{len(dq3)} ICMP packets from {src} within "
                    f"{icmp_cfg['time_window_seconds']}s "
                    f"(threshold {icmp_cfg['packet_threshold']})."
                ))

        # --- TCP SYN flood & repeated connection attempts -------------- #
        if pkt.get("protocol") == "TCP":
            flags = pkt.get("tcp_flags") or ""
            is_bare_syn = ("S" in flags) and ("A" not in flags)

            if is_bare_syn:
                syn_cfg = cfg["syn_flood"]
                dq4 = self.syn_window[src]
                dq4.append(now)
                self._trim(dq4, now, syn_cfg["time_window_seconds"])
                if len(dq4) >= syn_cfg["packet_threshold"]:
                    alerts.append(self._make_alert(
                        now, "TCP SYN Flood", src, dst, "Critical",
                        f"{len(dq4)} SYN packets from {src} within "
                        f"{syn_cfg['time_window_seconds']}s "
                        f"(threshold {syn_cfg['packet_threshold']})."
                    ))

                rc_cfg = cfg["repeated_connection"]
                key = (src, dst)
                dq5 = self.conn_window[key]
                dq5.append(now)
                self._trim(dq5, now, rc_cfg["time_window_seconds"])
                if len(dq5) >= rc_cfg["attempt_threshold"]:
                    alerts.append(self._make_alert(
                        now, "Repeated Connection Attempts", src, dst, "High",
                        f"{len(dq5)} connection attempts from {src} to {dst} within "
                        f"{rc_cfg['time_window_seconds']}s "
                        f"(threshold {rc_cfg['attempt_threshold']})."
                    ))

        return alerts

    # ------------------------------------------------------------------ #

    @staticmethod
    def _trim(dq, now, window_seconds):
        while dq and now - dq[0] > window_seconds:
            dq.popleft()

    @staticmethod
    def _make_alert(now, attack_type, src_ip, dst_ip, severity, reason):
        return {
            "timestamp": now,
            "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "attack_type": attack_type,
            "severity": severity,
            "reason": reason,
        }
