"""
traffic_simulator.py
A safe, fully synthetic traffic generator used for demos, presentations,
and grading environments where real packet capture isn't available or
desired (no Npcap, no admin rights, no interesting live traffic, or you
simply don't want to touch the real network).

It produces the exact same packet_info dict shape as packet_capture.py
and feeds it through the identical callback, so every other part of the
NIDS - the detector, alert manager, GUI, charts, logging - is exercised
exactly as it would be with real traffic. This module never touches the
network in any way; it only generates plain Python dictionaries.

WHY THE IP ADDRESSES LOOK LIKE THAT
------------------------------------
"Attacker" addresses are drawn from the IANA/RFC 5737 TEST-NET ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are permanently
reserved for documentation and example use and can never be routable on
the real internet. This makes it visually obvious in the Alerts table
that the traffic is synthetic, not a real attacker's address.
"""

import random
import threading
import time


class TrafficSimulator:
    LOCAL_IPS = [f"192.168.1.{i}" for i in (10, 11, 12, 15, 20, 34, 50)]
    REMOTE_IPS = ["8.8.8.8", "1.1.1.1", "142.250.190.14", "104.16.132.229",
                  "13.107.42.14", "151.101.1.69"]
    ATTACKER_IPS = ["203.0.113.7", "198.51.100.23", "192.0.2.44", "203.0.113.99"]
    GATEWAY_IP = "192.168.1.1"

    SCENARIOS = ["port_scan", "icmp_flood", "syn_flood", "suspicious_port"]

    def __init__(self, callback, on_error=None):
        self.callback = callback
        self.on_error = on_error
        self._stop_event = threading.Event()
        self._thread = None
        self.running = False
        self._scenario_queue = []
        self._lock = threading.Lock()

    def list_interfaces(self):
        """Mirrors PacketCapture.list_interfaces() so the GUI can treat
        both data sources interchangeably."""
        return [("Simulated Traffic (no real network adapter used)", None)]

    def start(self, interface=None):
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self.running = True
        self._thread.start()

    def stop(self, timeout=2):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self.running = False

    def trigger_scenario(self, name):
        """Queue an on-demand attack scenario, e.g. from a GUI button.
        Thread-safe: can be called from the Tk main thread."""
        if name not in self.SCENARIOS:
            return
        with self._lock:
            self._scenario_queue.append(name)

    # ------------------------------------------------------------------ #

    def _run_loop(self):
        try:
            next_auto_scenario = time.time() + random.uniform(15, 25)
            while not self._stop_event.is_set():
                scenario = None
                with self._lock:
                    if self._scenario_queue:
                        scenario = self._scenario_queue.pop(0)

                if scenario:
                    self._run_scenario(scenario)
                    continue

                if time.time() >= next_auto_scenario:
                    self._run_scenario(random.choice(self.SCENARIOS))
                    next_auto_scenario = time.time() + random.uniform(25, 45)
                    continue

                self._emit_normal_packet()
                time.sleep(random.uniform(0.05, 0.25))
        except Exception as e:
            self.running = False
            if self.on_error:
                self.on_error(f"Traffic simulator error: {e}")
            return
        self.running = False

    def _make_packet(self, src, dst, protocol, sport, dport, length, tcp_flags=None):
        pkt = {
            "timestamp": time.time(),
            "src_ip": src,
            "dst_ip": dst,
            "protocol": protocol,
            "src_port": sport,
            "dst_port": dport,
            "length": length,
            "tcp_flags": tcp_flags,
        }
        if protocol == "ICMP":
            pkt["icmp_type"] = 8  # echo request
        return pkt

    def _emit_normal_packet(self):
        src = random.choice(self.LOCAL_IPS)
        roll = random.random()
        if roll < 0.55:
            dst = random.choice(self.REMOTE_IPS)
            pkt = self._make_packet(
                src, dst, "TCP", random.randint(40000, 65000),
                random.choice([443, 443, 443, 80, 22]), random.randint(60, 1500),
                tcp_flags=random.choice(["S", "SA", "A", "PA"]),
            )
        elif roll < 0.85:
            dst = random.choice(self.REMOTE_IPS)
            pkt = self._make_packet(
                src, dst, "UDP", random.randint(40000, 65000), 53,
                random.randint(50, 300),
            )
        else:
            pkt = self._make_packet(src, self.GATEWAY_IP, "ICMP", None, None,
                                     random.randint(64, 100))
        self.callback(pkt)

    def _run_scenario(self, name):
        attacker = random.choice(self.ATTACKER_IPS)
        target = random.choice(self.LOCAL_IPS)

        if name == "port_scan":
            base_port = random.randint(1000, 8000)
            for i in range(random.randint(20, 30)):
                if self._stop_event.is_set():
                    return
                self.callback(self._make_packet(
                    attacker, target, "TCP", random.randint(40000, 65000),
                    base_port + i, random.randint(40, 80), tcp_flags="S"))
                time.sleep(0.02)

        elif name == "icmp_flood":
            for _ in range(random.randint(60, 90)):
                if self._stop_event.is_set():
                    return
                self.callback(self._make_packet(attacker, target, "ICMP", None, None, 98))
                time.sleep(0.015)

        elif name == "syn_flood":
            port = random.choice([80, 443, 22])
            for _ in range(random.randint(45, 70)):
                if self._stop_event.is_set():
                    return
                self.callback(self._make_packet(
                    attacker, target, "TCP", random.randint(40000, 65000),
                    port, 60, tcp_flags="S"))
                time.sleep(0.02)

        elif name == "suspicious_port":
            port = random.choice([3389, 4444, 23, 31337])
            self.callback(self._make_packet(
                attacker, target, "TCP", random.randint(40000, 65000),
                port, 60, tcp_flags="S"))
