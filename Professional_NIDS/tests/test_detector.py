"""
test_detector.py
Unit tests for IntrusionDetector's rule logic, using synthetic packet
dictionaries with controlled timestamps (no live capture needed, and no
real network traffic is generated or required to run these tests).

Run with:
    python -m unittest tests/test_detector.py
or simply:
    python -m unittest discover tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.intrusion_detector import IntrusionDetector


TEST_CONFIG = {
    "alert_dedup_seconds": 30,
    "port_scan": {"port_threshold": 5, "time_window_seconds": 10},
    "icmp_flood": {"packet_threshold": 5, "time_window_seconds": 5},
    "syn_flood": {"packet_threshold": 5, "time_window_seconds": 5},
    "high_packet_rate": {"packet_threshold": 10, "time_window_seconds": 5},
    "repeated_connection": {"attempt_threshold": 5, "time_window_seconds": 10},
    "suspicious_ports": [3389, 4444],
    "trusted_ips": ["10.0.0.1"],
}


def make_packet(t, src="10.0.0.5", dst="10.0.0.1", protocol="TCP",
                 src_port=50000, dst_port=80, length=60, tcp_flags="S"):
    return {
        "timestamp": t,
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "tcp_flags": tcp_flags,
    }


class TestIntrusionDetector(unittest.TestCase):
    def setUp(self):
        self.detector = IntrusionDetector(TEST_CONFIG)

    def test_port_scan_detected(self):
        alerts_seen = []
        base = 1000.0
        for i in range(6):
            pkt = make_packet(base + i * 0.1, dst_port=1000 + i)
            alerts_seen += self.detector.process_packet(pkt)
        types = [a["attack_type"] for a in alerts_seen]
        self.assertIn("Port Scan", types)

    def test_no_port_scan_below_threshold(self):
        alerts_seen = []
        base = 2000.0
        for i in range(3):
            pkt = make_packet(base + i * 0.1, dst_port=2000 + i)
            alerts_seen += self.detector.process_packet(pkt)
        types = [a["attack_type"] for a in alerts_seen]
        self.assertNotIn("Port Scan", types)

    def test_icmp_flood_detected(self):
        alerts_seen = []
        base = 3000.0
        for i in range(6):
            pkt = make_packet(base + i * 0.1, protocol="ICMP", dst_port=None, tcp_flags=None)
            alerts_seen += self.detector.process_packet(pkt)
        types = [a["attack_type"] for a in alerts_seen]
        self.assertIn("ICMP Flood", types)

    def test_syn_flood_detected(self):
        alerts_seen = []
        base = 4000.0
        for i in range(6):
            pkt = make_packet(base + i * 0.1, dst_port=80, tcp_flags="S")
            alerts_seen += self.detector.process_packet(pkt)
        types = [a["attack_type"] for a in alerts_seen]
        self.assertIn("TCP SYN Flood", types)

    def test_established_connections_do_not_trigger_syn_flood(self):
        alerts_seen = []
        base = 5000.0
        for i in range(10):
            # SYN+ACK ("SA") is a normal handshake reply, not a bare SYN.
            pkt = make_packet(base + i * 0.1, dst_port=80, tcp_flags="SA")
            alerts_seen += self.detector.process_packet(pkt)
        types = [a["attack_type"] for a in alerts_seen]
        self.assertNotIn("TCP SYN Flood", types)

    def test_suspicious_port_flagged_immediately(self):
        pkt = make_packet(6000.0, dst_port=3389, tcp_flags="S")
        alerts = self.detector.process_packet(pkt)
        types = [a["attack_type"] for a in alerts]
        self.assertIn("Suspicious Port Access", types)

    def test_high_packet_rate_detected(self):
        alerts_seen = []
        base = 7000.0
        for i in range(11):
            pkt = make_packet(base + i * 0.05, dst_port=443 + i)
            alerts_seen += self.detector.process_packet(pkt)
        types = [a["attack_type"] for a in alerts_seen]
        self.assertIn("High Packet Rate", types)

    def test_trusted_ip_never_generates_alerts(self):
        alerts_seen = []
        base = 9000.0
        for i in range(20):
            # Same behavior as the port-scan test, but from a whitelisted IP.
            pkt = make_packet(base + i * 0.05, src="10.0.0.1", dst_port=1000 + i, tcp_flags="S")
            alerts_seen += self.detector.process_packet(pkt)
        self.assertEqual(alerts_seen, [])

    def test_repeated_connection_attempts_detected(self):
        alerts_seen = []
        base = 8000.0
        for i in range(6):
            pkt = make_packet(base + i * 0.1, dst="10.0.0.99", dst_port=80, tcp_flags="S")
            alerts_seen += self.detector.process_packet(pkt)
        types = [a["attack_type"] for a in alerts_seen]
        self.assertIn("Repeated Connection Attempts", types)


if __name__ == "__main__":
    unittest.main()
