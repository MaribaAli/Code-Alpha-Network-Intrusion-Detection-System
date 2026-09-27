"""
main.py
Entry point for the Professional Network Intrusion Detection System.

Run with:
    python main.py

On Windows, this generally needs to run in a terminal opened as
Administrator (or VS Code itself run as Administrator), because Scapy/
Npcap require elevated privileges to open a network interface for
live capture.
"""

import os
import sys
import json
import tkinter as tk
from tkinter import messagebox

DEFAULT_CONFIG = {
    "log_dir": "logs",
    "data_dir": "data",
    "enable_blocking": False,
    "sound_alerts": False,
    "simulation_mode": True,
    "accent_color": "Teal",
    "theme": "Dark",
    "alert_dedup_seconds": 30,
    "trusted_ips": [],
    "port_scan": {"port_threshold": 15, "time_window_seconds": 10},
    "icmp_flood": {"packet_threshold": 50, "time_window_seconds": 5},
    "syn_flood": {"packet_threshold": 40, "time_window_seconds": 5},
    "high_packet_rate": {"packet_threshold": 200, "time_window_seconds": 5},
    "repeated_connection": {"attempt_threshold": 20, "time_window_seconds": 15},
    "suspicious_ports": [23, 135, 445, 1337, 3389, 4444, 5555, 6667, 31337],
    "gui": {"refresh_interval_ms": 200, "chart_refresh_ms": 1500, "max_packets_displayed": 500},
}


def load_config(path="config.json"):
    if not os.path.exists(path):
        return dict(DEFAULT_CONFIG)
    try:
        with open(path, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        cfg = dict(DEFAULT_CONFIG)
        cfg.update(user_cfg)
        return cfg
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: could not read config.json ({e}). Using default configuration.")
        return dict(DEFAULT_CONFIG)


def main():
    # Make sure "src" is importable when run from the project root.
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    config = load_config(os.path.join(project_root, "config.json"))

    if not config.get("simulation_mode", True):
        try:
            import scapy  # noqa: F401
        except ImportError:
            print(
                "\nERROR: The 'scapy' package is not installed, and simulation_mode is off "
                "in config.json.\n"
                "Either install scapy:\n"
                "    pip install -r requirements.txt\n"
                "or set \"simulation_mode\": true in config.json to run with synthetic "
                "demo traffic instead (no scapy/Npcap/admin rights required).\n"
            )
            sys.exit(1)

    os.makedirs(os.path.join(project_root, config.get("log_dir", "logs")), exist_ok=True)
    os.makedirs(os.path.join(project_root, config.get("data_dir", "data")), exist_ok=True)

    from src.dashboard import NIDSApp

    root = tk.Tk()
    try:
        app = NIDSApp(root, config)
        root.mainloop()
    except Exception as e:
        try:
            messagebox.showerror("Fatal Error", f"The application encountered an error:\n{e}")
        except Exception:
            print(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
