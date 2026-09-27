"""
dashboard.py
The complete Tkinter GUI for the Professional Network Intrusion Detection
System.

Design goals for this version:
 - A distinctive, custom-drawn look (canvas-based stat cards and a
   circular "Network Health" gauge) rather than plain default widgets.
 - A real, switchable Dark / Light theme (not just an accent color),
   applied via a full UI rebuild so every widget is guaranteed correct -
   no half-themed leftovers.
 - Genuinely working extra features: top talkers, live bandwidth chart,
   packet detail inspection, sortable tables, alert search/severity
   filtering, IP whitelisting, optional sound alerts on Critical events,
   session report export, and a switchable accent color.
 - Still fully thread-safe: PacketCapture runs Scapy's sniff() on a
   background thread and only ever pushes data into queue.Queue objects.
   All widget updates happen on the Tk main thread via root.after() polling.
"""

import os
import time
import json
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from collections import Counter, deque

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from src.packet_capture import PacketCapture
from src.traffic_simulator import TrafficSimulator
from src.intrusion_detector import IntrusionDetector
from src.alert_manager import AlertManager
from src.logger import Logger
from src import utils

# ---------------------------------------------------------------------- #
# Themes: everything color-related lives here. Switching themes rebuilds
# the whole UI from scratch using the selected palette, so there is no
# risk of a widget being left over in the "wrong" color.
# ---------------------------------------------------------------------- #
THEMES = {
    "Dark": {
        "bg": "#0a0e17",
        "panel": "#131a29",
        "panel_alt": "#182036",
        "sidebar": "#080b12",
        "text": "#e7ebf3",
        "muted": "#8b93a7",
        "border": "#232d45",
        "danger": "#e74c3c",
        "warn": "#f1c40f",
        "high": "#e67e22",
        "ok": "#2ecc71",
        "entry_bg": "#182036",
        "selected_fg": "#052018",
    },
    "Light": {
        "bg": "#eef1f7",
        "panel": "#ffffff",
        "panel_alt": "#f3f5fb",
        "sidebar": "#ffffff",
        "text": "#1a2233",
        "muted": "#5b6472",
        "border": "#d7deea",
        "danger": "#dc2626",
        "warn": "#ca8a04",
        "high": "#ea580c",
        "ok": "#15803d",
        "entry_bg": "#f3f5fb",
        "selected_fg": "#ffffff",
    },
}

DEFAULT_ACCENT = "#00d4aa"


# ======================================================================== #
# Small custom-drawn widgets (give the GUI a distinctive, non-default look)
# ======================================================================== #

class StatCard(tk.Canvas):
    """A rounded-rectangle stat card drawn on a Canvas: icon, big value, label."""

    def __init__(self, parent, icon, label, color, theme, **kwargs):
        kwargs.setdefault("bg", theme["bg"])
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(parent, **kwargs)
        self.icon = icon
        self.label_text = label
        self.color = color
        self.theme = theme
        self.value_text = "0"
        self.bind("<Configure>", lambda e: self._redraw())
        self._redraw()

    def set_value(self, value):
        self.value_text = str(value)
        self._redraw()

    def set_color(self, color):
        self.color = color
        self._redraw()

    def _rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)

    def _redraw(self):
        self.delete("all")
        t = self.theme
        w = max(self.winfo_width(), 160)
        h = max(self.winfo_height(), 90)
        self._rounded_rect(2, 2, w - 2, h - 2, 14, fill=t["panel"], outline=t["border"], width=1)
        self._rounded_rect(2, 2, 6, h - 2, 3, fill=self.color, outline=self.color)
        self.create_text(20, 20, text=self.icon, anchor="nw", font=("Segoe UI Emoji", 15))
        self.create_text(w - 18, h / 2 - 4, text=self.value_text, anchor="e",
                          font=("Segoe UI", 21, "bold"), fill=self.color)
        self.create_text(20, h - 18, text=self.label_text, anchor="sw",
                          font=("Segoe UI", 9), fill=t["muted"])


class HealthGauge(tk.Canvas):
    """A circular gauge (0-100) showing an at-a-glance 'Network Health' score."""

    def __init__(self, parent, theme, **kwargs):
        kwargs.setdefault("bg", theme["bg"])
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(parent, **kwargs)
        self.theme = theme
        self.score = 100
        self.bind("<Configure>", lambda e: self._redraw())
        self._redraw()

    def set_score(self, score):
        self.score = max(0, min(100, score))
        self._redraw()

    def _redraw(self):
        self.delete("all")
        t = self.theme
        w = max(self.winfo_width(), 160)
        h = max(self.winfo_height(), 160)
        size = min(w, h) - 26
        x0, y0 = (w - size) / 2, (h - size) / 2
        x1, y1 = x0 + size, y0 + size

        self.create_oval(x0, y0, x1, y1, fill=t["panel"], outline=t["border"], width=1)
        self.create_arc(x0 + 8, y0 + 8, x1 - 8, y1 - 8, start=90, extent=359.9,
                         style="arc", width=12, outline=t["panel_alt"])

        if self.score >= 70:
            color = t["ok"]
        elif self.score >= 40:
            color = t["warn"]
        else:
            color = t["danger"]

        extent = -(self.score / 100.0 * 359.9) if self.score > 0 else -0.1
        self.create_arc(x0 + 8, y0 + 8, x1 - 8, y1 - 8, start=90, extent=extent,
                         style="arc", width=12, outline=color)

        self.create_text(w / 2, h / 2 - 8, text=f"{int(self.score)}",
                          font=("Segoe UI", 24, "bold"), fill=t["text"])
        self.create_text(w / 2, h / 2 + 18, text="NETWORK HEALTH",
                          font=("Segoe UI", 8, "bold"), fill=t["muted"])


# ======================================================================== #
# Main application
# ======================================================================== #

class NIDSApp:
    def __init__(self, root, config):
        self.root = root
        self.config = config

        self.accent = utils.ACCENT_PRESETS.get(config.get("accent_color", "Teal"), DEFAULT_ACCENT)
        self.theme_name = config.get("theme", "Dark")
        if self.theme_name not in THEMES:
            self.theme_name = "Dark"
        self.theme = THEMES[self.theme_name]

        self.root.title("Professional Network Intrusion Detection System")
        self.root.geometry("1360x840")
        self.root.minsize(1180, 720)

        # --- Core components ------------------------------------------------
        self.logger = Logger(log_dir=config.get("log_dir", "logs"))
        self.data_dir = config.get("data_dir", "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.alert_manager = AlertManager(config, self.logger)
        self.detector = IntrusionDetector(config)
        self.capture = PacketCapture(callback=self._on_packet, on_error=self._on_capture_error)
        self.simulator = TrafficSimulator(callback=self._on_packet, on_error=self._on_capture_error)
        self.active_source = None

        self.packet_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.error_queue = queue.Queue()

        # --- Live stats ------------------------------------------------------
        self.total_packets = 0
        self.total_bytes = 0
        self.total_alerts = 0
        self.high_severity_count = 0
        self.severity_counts = Counter()
        self.unique_src_ips = set()
        self.protocol_counts = Counter()
        self.attack_type_counts = Counter()
        self.alert_time_buckets = deque()
        self.src_ip_counts = Counter()
        self.bandwidth_buckets = {}  # epoch_second -> bytes
        self.all_alerts_list = []
        self.latest_alert = None
        self.session_start_time = None

        self.packet_rows = {}
        self.displayed_packet_ids = deque()
        self.max_display_packets = config.get("gui", {}).get("max_packets_displayed", 500)
        self.packet_log = deque(maxlen=5000)

        # --- Filters / toggles ------------------------------------------------
        self.filter_protocol = tk.StringVar(value="All")
        self.filter_src = tk.StringVar()
        self.filter_dst = tk.StringVar()
        self.auto_scroll = tk.BooleanVar(value=True)

        self.alert_search = tk.StringVar()
        self.alert_severity_filter = tk.StringVar(value="All")

        # --- Settings ------------------------------------------------------
        self.enable_blocking = tk.BooleanVar(value=bool(config.get("enable_blocking", False)))
        self.sound_alerts = tk.BooleanVar(value=bool(config.get("sound_alerts", False)))
        self.simulation_mode = tk.BooleanVar(value=bool(config.get("simulation_mode", True)))
        self.accent_choice = tk.StringVar(value=config.get("accent_color", "Teal"))
        self.theme_choice = tk.StringVar(value=self.theme_name)
        self.iface_map = {}
        self.selected_iface_display = tk.StringVar(value="Default (let OS choose)")
        self.current_frame_key = "dashboard"

        self._build_style()
        self._build_ui()
        self._apply_accent()

        refresh_ms = config.get("gui", {}).get("refresh_interval_ms", 200)
        self.root.after(refresh_ms, self._poll_queues)

        chart_ms = config.get("gui", {}).get("chart_refresh_ms", 1500)
        self.root.after(chart_ms, self._refresh_charts)
        self.root.after(1000, self._tick_uptime)
        self.root.after(300, self._refresh_firewall_button)

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ==================================================================== #
    # Theme / severity color helpers
    # ==================================================================== #

    def _severity_color(self, severity):
        mapping = {"Low": "ok", "Medium": "warn", "High": "high", "Critical": "danger"}
        return self.theme.get(mapping.get(severity, "muted"), self.theme["muted"])

    def _toggle_theme(self):
        self._set_theme("Light" if self.theme_name == "Dark" else "Dark")

    def _change_theme_from_settings(self):
        self._set_theme(self.theme_choice.get())

    def _set_theme(self, name):
        if name not in THEMES or name == self.theme_name and self.theme is THEMES[name]:
            pass
        if name not in THEMES:
            return

        self.theme_name = name
        self.theme = THEMES[name]
        self.theme_choice.set(name)

        was_running = self.capture.running or self.simulator.running
        was_simulated = self.active_source is self.simulator
        latest_alert_snapshot = self.latest_alert

        self.sidebar.destroy()
        self.content.destroy()

        self._build_style()
        self._build_ui()
        self._apply_accent()

        if was_running:
            self.status_label.configure(
                text="\u25CF LIVE (Simulated)" if was_simulated else "\u25CF LIVE", fg=self.accent)
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            if hasattr(self, "data_source_badge"):
                self.data_source_badge.configure(text="\u26A0 SIMULATED DATA" if was_simulated else "")

        if latest_alert_snapshot:
            color = self._severity_color(latest_alert_snapshot["severity"])
            self.latest_alert_label.configure(
                text=f"[{latest_alert_snapshot['severity']}] {latest_alert_snapshot['attack_type']}\n"
                     f"{latest_alert_snapshot['src_ip']} -> {latest_alert_snapshot['dst_ip']}\n"
                     f"{latest_alert_snapshot['reason']}",
                fg=color
            )

        self._render_alerts_from_filter()
        self._repopulate_packet_table()
        self._update_stat_cards()
        self._draw_charts_only()

    # ==================================================================== #
    # UI construction
    # ==================================================================== #

    def _build_style(self):
        t = self.theme
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Treeview",
                         background=t["panel_alt"], foreground=t["text"],
                         fieldbackground=t["panel_alt"], borderwidth=0,
                         rowheight=24, font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                         background=t["border"], foreground=t["text"],
                         relief="flat", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", self.accent)],
                  foreground=[("selected", t["selected_fg"])])
        style.map("Treeview.Heading", background=[("active", t["panel_alt"])])

        style.configure("TCombobox", fieldbackground=t["entry_bg"], background=t["entry_bg"],
                         foreground=t["text"])
        style.configure("TCheckbutton", background=t["panel"], foreground=t["text"])
        style.configure("TFrame", background=t["panel"])

    def _build_ui(self):
        t = self.theme
        self.root.configure(bg=t["bg"])

        self.sidebar = tk.Frame(self.root, bg=t["sidebar"], width=225)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        title_row = tk.Frame(self.sidebar, bg=t["sidebar"])
        title_row.pack(fill="x", pady=(18, 0))
        self.title_label = tk.Label(title_row, text="\U0001F6E1  NIDS", bg=t["sidebar"], fg=self.accent,
                                     font=("Segoe UI", 16, "bold"))
        self.title_label.pack(side="left", padx=(18, 0))
        theme_icon = "\u2600" if self.theme_name == "Dark" else "\U0001F319"
        self.theme_toggle_btn = tk.Button(title_row, text=theme_icon, command=self._toggle_theme,
                                           bg=t["sidebar"], fg=t["muted"], activebackground=t["panel_alt"],
                                           font=("Segoe UI", 11), relief="flat", cursor="hand2", bd=0,
                                           width=2)
        self.theme_toggle_btn.pack(side="right", padx=(0, 14))

        tk.Label(self.sidebar, text="Network Intrusion\nDetection System",
                 bg=t["sidebar"], fg=t["muted"], font=("Segoe UI", 8), justify="left",
                 anchor="w", padx=18).pack(fill="x", pady=(4, 16))

        self.status_label = tk.Label(self.sidebar, text="\u25CF STOPPED", bg=t["sidebar"], fg=t["danger"],
                                      font=("Segoe UI", 11, "bold"), anchor="w", padx=18)
        self.status_label.pack(fill="x")

        self.uptime_label = tk.Label(self.sidebar, text="Uptime: 00:00:00", bg=t["sidebar"], fg=t["muted"],
                                      font=("Segoe UI", 8), anchor="w", padx=18)
        self.uptime_label.pack(fill="x", pady=(0, 14))

        self.start_btn = tk.Button(self.sidebar, text="\u25B6  Start Monitoring", command=self._start_monitoring,
                                    bg=self.accent, fg="#052018", activebackground="#00e6b8",
                                    font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2", pady=8, bd=0)
        self.start_btn.pack(fill="x", padx=16, pady=(0, 8))

        self.stop_btn = tk.Button(self.sidebar, text="\u25A0  Stop Monitoring", command=self._stop_monitoring,
                                   bg="#3a2230", fg=t["danger"], activebackground="#4a2b3d",
                                   font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2",
                                   pady=8, state="disabled", bd=0)
        self.stop_btn.pack(fill="x", padx=16, pady=(0, 24))

        self.firewall_btn = tk.Button(self.sidebar, text="\U0001F6E1  Firewall: ...", command=self._toggle_firewall,
                                       bg=t["panel_alt"], fg=t["text"], activebackground=t["border"],
                                       font=("Segoe UI", 9, "bold"), relief="flat", cursor="hand2",
                                       pady=6, bd=0)
        self.firewall_btn.pack(fill="x", padx=16, pady=(0, 20))

        nav_items = [
            ("\U0001F4CA  Dashboard", "dashboard"),
            ("\U0001F4E1  Live Packets", "packets"),
            ("\U0001F6A8  Alerts", "alerts"),
            ("\u2699  Settings", "settings"),
        ]
        self.nav_buttons = {}
        self.nav_indicators = {}
        for label, key in nav_items:
            row = tk.Frame(self.sidebar, bg=t["sidebar"])
            row.pack(fill="x")
            indicator = tk.Frame(row, bg=t["sidebar"], width=4)
            indicator.pack(side="left", fill="y")
            btn = tk.Button(row, text=label, command=lambda k=key: self._show_frame(k),
                             bg=t["sidebar"], fg=t["text"], activebackground=t["panel_alt"],
                             activeforeground=self.accent,
                             font=("Segoe UI", 10), relief="flat", anchor="w", padx=16, pady=10,
                             cursor="hand2", bd=0)
            btn.pack(side="left", fill="x", expand=True)
            self.nav_buttons[key] = btn
            self.nav_indicators[key] = indicator

        tk.Label(self.sidebar, text="Defensive monitoring only.\nNo automatic offensive actions.",
                 bg=t["sidebar"], fg=t["muted"], font=("Segoe UI", 7), justify="left", anchor="sw",
                 wraplength=190, padx=18).pack(side="bottom", fill="x", pady=16)

        self.content = tk.Frame(self.root, bg=t["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        self.frames = {}
        self._build_dashboard_frame()
        self._build_packets_frame()
        self._build_alerts_frame()
        self._build_settings_frame()

        self._on_simulation_mode_changed()
        self._show_frame(self.current_frame_key)

    # -- Dashboard frame -------------------------------------------------- #

    def _build_dashboard_frame(self):
        t = self.theme
        frame = tk.Frame(self.content, bg=t["bg"])
        self.frames["dashboard"] = frame

        header_row = tk.Frame(frame, bg=t["bg"])
        header_row.pack(fill="x", padx=24, pady=(20, 10))
        tk.Label(header_row, text="Dashboard", bg=t["bg"], fg=t["text"],
                 font=("Segoe UI", 16, "bold")).pack(side="left")
        self.data_source_badge = tk.Label(header_row, text="", bg=t["bg"], fg=t["warn"],
                                           font=("Segoe UI", 9, "bold"))
        self.data_source_badge.pack(side="left", padx=(12, 0))
        tk.Button(header_row, text="\U0001F4C4 Generate Session Report", command=self._generate_report,
                  bg=t["panel_alt"], fg=t["text"], relief="flat", padx=12, pady=4,
                  cursor="hand2").pack(side="right")

        # Stat cards
        cards_row = tk.Frame(frame, bg=t["bg"])
        cards_row.pack(fill="x", padx=24)
        self.stat_cards = {}
        card_defs = [
            ("total_packets", "\U0001F4E6", "Total Packets", self.accent),
            ("total_bytes", "\U0001F4E1", "Data Captured", "#3b82f6"),
            ("total_alerts", "\u26A0", "Total Alerts", t["warn"]),
            ("high_severity", "\U0001F525", "High/Critical", t["danger"]),
            ("unique_ips", "\U0001F310", "Unique Source IPs", t["ok"]),
        ]
        for key, icon, label, color in card_defs:
            card = StatCard(cards_row, icon, label, color, t, height=100, width=200)
            card.pack(side="left", expand=True, fill="both", padx=6)
            self.stat_cards[key] = card

        # Health gauge + Top talkers + latest alert banner
        mid_row = tk.Frame(frame, bg=t["bg"])
        mid_row.pack(fill="x", padx=24, pady=(16, 10))

        gauge_box = tk.Frame(mid_row, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        gauge_box.pack(side="left", fill="y", padx=(0, 8))
        self.health_gauge = HealthGauge(gauge_box, t, width=190, height=190)
        self.health_gauge.pack(padx=6, pady=6)

        talkers_box = tk.Frame(mid_row, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        talkers_box.pack(side="left", fill="both", expand=True, padx=8)
        tk.Label(talkers_box, text="Top Talkers (by packet count)", bg=t["panel"], fg=t["text"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(10, 4))
        self.talkers_tree = ttk.Treeview(talkers_box, columns=("rank", "ip", "count", "pct"),
                                          show="headings", height=6)
        for c, txt, w in [("rank", "#", 30), ("ip", "Source IP", 150), ("count", "Packets", 90),
                          ("pct", "% of Total", 90)]:
            self.talkers_tree.heading(c, text=txt)
            self.talkers_tree.column(c, width=w, anchor="w")
        self.talkers_tree.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        banner_box = tk.Frame(mid_row, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        banner_box.pack(side="left", fill="both", expand=True, padx=(8, 0))
        tk.Label(banner_box, text="Latest Alert", bg=t["panel"], fg=t["text"],
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(10, 4))
        self.latest_alert_label = tk.Label(banner_box, text="No alerts yet.", bg=t["panel"], fg=t["muted"],
                                            font=("Segoe UI", 9), wraplength=260, justify="left", anchor="nw")
        self.latest_alert_label.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Charts (2x2 grid)
        charts_frame = tk.Frame(frame, bg=t["bg"])
        charts_frame.pack(fill="both", expand=True, padx=24, pady=(6, 20))

        self.fig = Figure(figsize=(11, 5.6), dpi=90, facecolor=t["bg"])
        self.ax_attack = self.fig.add_subplot(221)
        self.ax_proto = self.fig.add_subplot(222)
        self.ax_time = self.fig.add_subplot(223)
        self.ax_bw = self.fig.add_subplot(224)
        for ax in (self.ax_attack, self.ax_proto, self.ax_time, self.ax_bw):
            ax.set_facecolor(t["panel_alt"])
            ax.tick_params(colors=t["muted"], labelsize=7)
            for spine in ax.spines.values():
                spine.set_color(t["border"])

        self.canvas = FigureCanvasTkAgg(self.fig, master=charts_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self._redraw_charts_placeholder()

    def _redraw_charts_placeholder(self):
        t = self.theme
        self.ax_attack.clear()
        self.ax_attack.set_title("Attack Type Distribution", color=t["text"], fontsize=9)
        self.ax_proto.clear()
        self.ax_proto.set_title("Protocol Distribution", color=t["text"], fontsize=9)
        self.ax_time.clear()
        self.ax_time.set_title("Alerts Over Time", color=t["text"], fontsize=9)
        self.ax_bw.clear()
        self.ax_bw.set_title("Bandwidth (KB/s)", color=t["text"], fontsize=9)
        self.canvas.draw_idle()

    # -- Live Packets frame ------------------------------------------------ #

    def _build_packets_frame(self):
        t = self.theme
        frame = tk.Frame(self.content, bg=t["bg"])
        self.frames["packets"] = frame

        header = tk.Label(frame, text="Live Packets", bg=t["bg"], fg=t["text"], font=("Segoe UI", 16, "bold"))
        header.pack(anchor="w", padx=24, pady=(20, 10))

        filter_row = tk.Frame(frame, bg=t["bg"])
        filter_row.pack(fill="x", padx=24, pady=(0, 10))

        tk.Label(filter_row, text="Protocol:", bg=t["bg"], fg=t["muted"], font=("Segoe UI", 9)).pack(side="left")
        ttk.Combobox(filter_row, textvariable=self.filter_protocol, width=10, state="readonly",
                     values=["All", "TCP", "UDP", "ICMP", "OTHER"]).pack(side="left", padx=(6, 16))

        tk.Label(filter_row, text="Src IP:", bg=t["bg"], fg=t["muted"], font=("Segoe UI", 9)).pack(side="left")
        tk.Entry(filter_row, textvariable=self.filter_src, width=16, bg=t["entry_bg"], fg=t["text"],
                  insertbackground=t["text"], relief="flat").pack(side="left", padx=(6, 16))

        tk.Label(filter_row, text="Dst IP:", bg=t["bg"], fg=t["muted"], font=("Segoe UI", 9)).pack(side="left")
        tk.Entry(filter_row, textvariable=self.filter_dst, width=16, bg=t["entry_bg"], fg=t["text"],
                  insertbackground=t["text"], relief="flat").pack(side="left", padx=(6, 16))

        ttk.Checkbutton(filter_row, text="Auto-scroll", variable=self.auto_scroll).pack(side="left", padx=(0, 16))

        tk.Button(filter_row, text="Reset Filters", command=self._reset_packet_filters,
                  bg=t["panel_alt"], fg=t["text"], relief="flat", padx=10, cursor="hand2").pack(side="left", padx=(0, 8))
        tk.Button(filter_row, text="Export Packets to CSV", command=self._export_packets_csv,
                  bg=t["panel_alt"], fg=t["text"], relief="flat", padx=10, cursor="hand2").pack(side="left")

        table_frame = tk.Frame(frame, bg=t["bg"])
        table_frame.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        cols = ("time", "src", "dst", "proto", "sport", "dport", "len")
        headers = {"time": "Timestamp", "src": "Source IP", "dst": "Destination IP",
                   "proto": "Protocol", "sport": "Src Port", "dport": "Dst Port", "len": "Length"}
        self.packets_tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        for c in cols:
            self.packets_tree.heading(c, text=headers[c],
                                       command=lambda c=c: self._sort_by_column(self.packets_tree, c, False))
            self.packets_tree.column(c, width=140 if c in ("src", "dst") else 100, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.packets_tree.yview)
        self.packets_tree.configure(yscrollcommand=vsb.set)
        self.packets_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.packets_tree.bind("<Double-1>", self._show_packet_detail)

        tk.Label(frame, text="Double-click any packet row for full details.",
                 bg=t["bg"], fg=t["muted"], font=("Segoe UI", 8, "italic")).pack(anchor="w", padx=24, pady=(0, 10))

    def _reset_packet_filters(self):
        self.filter_protocol.set("All")
        self.filter_src.set("")
        self.filter_dst.set("")

    # -- Alerts frame -------------------------------------------------- #

    def _build_alerts_frame(self):
        t = self.theme
        frame = tk.Frame(self.content, bg=t["bg"])
        self.frames["alerts"] = frame

        header = tk.Label(frame, text="Alerts", bg=t["bg"], fg=t["text"], font=("Segoe UI", 16, "bold"))
        header.pack(anchor="w", padx=24, pady=(20, 10))

        filter_row = tk.Frame(frame, bg=t["bg"])
        filter_row.pack(fill="x", padx=24, pady=(0, 8))
        tk.Label(filter_row, text="Search:", bg=t["bg"], fg=t["muted"], font=("Segoe UI", 9)).pack(side="left")
        search_entry = tk.Entry(filter_row, textvariable=self.alert_search, width=24, bg=t["entry_bg"],
                                 fg=t["text"], insertbackground=t["text"], relief="flat")
        search_entry.pack(side="left", padx=(6, 16))
        search_entry.bind("<KeyRelease>", lambda e: self._render_alerts_from_filter())

        tk.Label(filter_row, text="Severity:", bg=t["bg"], fg=t["muted"], font=("Segoe UI", 9)).pack(side="left")
        sev_combo = ttk.Combobox(filter_row, textvariable=self.alert_severity_filter, width=10, state="readonly",
                                  values=["All", "Low", "Medium", "High", "Critical"])
        sev_combo.pack(side="left", padx=(6, 16))
        sev_combo.bind("<<ComboboxSelected>>", lambda e: self._render_alerts_from_filter())

        btn_row = tk.Frame(frame, bg=t["bg"])
        btn_row.pack(fill="x", padx=24, pady=(0, 10))
        tk.Button(btn_row, text="Clear Displayed Alerts", command=self._clear_alerts,
                  bg=t["panel_alt"], fg=t["text"], relief="flat", padx=10, cursor="hand2").pack(side="left", padx=(0, 8))
        tk.Button(btn_row, text="Export Alerts to CSV", command=self._export_alerts_csv,
                  bg=t["panel_alt"], fg=t["text"], relief="flat", padx=10, cursor="hand2").pack(side="left", padx=(0, 8))
        tk.Button(btn_row, text="Block Selected Source (local firewall)", command=self._block_selected,
                  bg="#3a2230", fg=t["danger"], relief="flat", padx=10, cursor="hand2").pack(side="left")

        table_frame = tk.Frame(frame, bg=t["bg"])
        table_frame.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        cols = ("time", "src", "dst", "type", "severity", "desc")
        headers = {"time": "Date/Time", "src": "Source IP", "dst": "Destination IP",
                   "type": "Attack Type", "severity": "Severity", "desc": "Description"}
        self.alerts_tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        for c in cols:
            self.alerts_tree.heading(c, text=headers[c],
                                      command=lambda c=c: self._sort_by_column(self.alerts_tree, c, False))
            width = 340 if c == "desc" else (150 if c in ("src", "dst") else 120)
            self.alerts_tree.column(c, width=width, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=vsb.set)
        self.alerts_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.alerts_tree.tag_configure("Low", foreground=t["ok"])
        self.alerts_tree.tag_configure("Medium", foreground=t["warn"])
        self.alerts_tree.tag_configure("High", foreground=t["high"])
        self.alerts_tree.tag_configure("Critical", foreground=t["danger"])

    # -- Settings frame -------------------------------------------------- #

    def _build_settings_frame(self):
        t = self.theme
        frame = tk.Frame(self.content, bg=t["bg"])
        self.frames["settings"] = frame

        header = tk.Label(frame, text="Settings", bg=t["bg"], fg=t["text"], font=("Segoe UI", 16, "bold"))
        header.pack(anchor="w", padx=24, pady=(20, 10))

        source_frame = tk.Frame(frame, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        source_frame.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(source_frame, text="Data Source", bg=t["panel"], fg=t["text"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        tk.Label(source_frame,
                 text="Simulated mode generates realistic synthetic traffic (including occasional "
                      "demo attacks) entirely in software - no real packets are sent or captured, "
                      "and no admin rights or Npcap are required. Turn this off to capture real "
                      "traffic from a network adapter below instead.",
                 bg=t["panel"], fg=t["muted"], font=("Segoe UI", 8), wraplength=700,
                 justify="left").pack(anchor="w", padx=16, pady=(0, 8))
        ttk.Checkbutton(source_frame, text="Use Simulated Traffic Generator (recommended for demos)",
                         variable=self.simulation_mode,
                         command=self._on_simulation_mode_changed).pack(anchor="w", padx=16, pady=(0, 10))

        tk.Label(source_frame, text="Trigger a demo attack now (simulation mode must be running):",
                 bg=t["panel"], fg=t["muted"], font=("Segoe UI", 8, "italic")).pack(
                 anchor="w", padx=16, pady=(0, 6))
        scenario_btn_row = tk.Frame(source_frame, bg=t["panel"])
        scenario_btn_row.pack(fill="x", padx=16, pady=(0, 14))
        for label, name in [("Port Scan", "port_scan"), ("ICMP Flood", "icmp_flood"),
                             ("SYN Flood", "syn_flood"), ("Suspicious Port", "suspicious_port")]:
            tk.Button(scenario_btn_row, text=label, command=lambda n=name: self._trigger_demo_scenario(n),
                      bg=t["panel_alt"], fg=t["text"], relief="flat", padx=10, pady=4,
                      cursor="hand2").pack(side="left", padx=(0, 8))

        iface_frame = tk.Frame(frame, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        iface_frame.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(iface_frame, text="Capture Interface", bg=t["panel"], fg=t["text"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        tk.Label(iface_frame, text="Only used when Simulated Traffic Generator is turned off above. "
                                    "Select which real network adapter to monitor before pressing "
                                    "Start Monitoring.", bg=t["panel"], fg=t["muted"], font=("Segoe UI", 8),
                 wraplength=700, justify="left").pack(anchor="w", padx=16)

        row = tk.Frame(iface_frame, bg=t["panel"])
        row.pack(fill="x", padx=16, pady=12)
        self.iface_combo = ttk.Combobox(row, textvariable=self.selected_iface_display, width=60, state="readonly")
        self.iface_combo.pack(side="left")
        tk.Button(row, text="Refresh List", command=self._refresh_interfaces,
                  bg=t["panel_alt"], fg=t["text"], relief="flat", padx=10, cursor="hand2").pack(side="left", padx=8)
        self._refresh_interfaces()

        thresh_frame = tk.Frame(frame, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        thresh_frame.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(thresh_frame, text="Detection Thresholds (from config.json)", bg=t["panel"], fg=t["text"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        tk.Label(thresh_frame, text=self._format_thresholds(), bg=t["panel"], fg=t["muted"], font=("Consolas", 9),
                 justify="left", anchor="w").pack(anchor="w", padx=16, pady=(0, 6))
        trusted = self.config.get("trusted_ips", [])
        trusted_text = ("Trusted/whitelisted IPs (never alerted on): " + ", ".join(trusted)) if trusted \
            else "Trusted/whitelisted IPs: none configured."
        tk.Label(thresh_frame, text=trusted_text, bg=t["panel"], fg=t["muted"], font=("Consolas", 9),
                 justify="left", anchor="w", wraplength=760).pack(anchor="w", padx=16, pady=(0, 6))
        tk.Label(thresh_frame, text="To change thresholds or the trusted-IP list, edit config.json and restart.",
                 bg=t["panel"], fg=t["muted"], font=("Segoe UI", 8, "italic")).pack(anchor="w", padx=16, pady=(0, 12))

        appearance_frame = tk.Frame(frame, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        appearance_frame.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(appearance_frame, text="Appearance", bg=t["panel"], fg=t["text"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(12, 4))

        theme_row = tk.Frame(appearance_frame, bg=t["panel"])
        theme_row.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(theme_row, text="Theme:", bg=t["panel"], fg=t["muted"], font=("Segoe UI", 9)).pack(side="left")
        theme_combo = ttk.Combobox(theme_row, textvariable=self.theme_choice, width=12, state="readonly",
                                    values=list(THEMES.keys()))
        theme_combo.pack(side="left", padx=8)
        theme_combo.bind("<<ComboboxSelected>>", lambda e: self._change_theme_from_settings())

        acc_row = tk.Frame(appearance_frame, bg=t["panel"])
        acc_row.pack(fill="x", padx=16, pady=(0, 12))
        tk.Label(acc_row, text="Accent Color:", bg=t["panel"], fg=t["muted"], font=("Segoe UI", 9)).pack(side="left")
        accent_combo = ttk.Combobox(acc_row, textvariable=self.accent_choice, width=12, state="readonly",
                                     values=list(utils.ACCENT_PRESETS.keys()))
        accent_combo.pack(side="left", padx=8)
        accent_combo.bind("<<ComboboxSelected>>", lambda e: self._change_accent())

        alerts_frame = tk.Frame(frame, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        alerts_frame.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(alerts_frame, text="Alert Behavior", bg=t["panel"], fg=t["text"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        ttk.Checkbutton(alerts_frame, text="Play a sound on Critical severity alerts",
                         variable=self.sound_alerts).pack(anchor="w", padx=16, pady=(0, 12))

        block_frame = tk.Frame(frame, bg=t["panel"], highlightbackground=t["border"], highlightthickness=1)
        block_frame.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(block_frame, text="Response Actions", bg=t["panel"], fg=t["text"],
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        tk.Label(block_frame,
                 text="Disabled by default. When enabled, the 'Block Selected Source' button on the Alerts "
                      "page can add a local Windows Firewall rule blocking traffic to/from a chosen IP. "
                      "This never runs automatically and never sends any traffic to a remote host - it only "
                      "changes your own machine's firewall configuration, and always asks for confirmation.",
                 bg=t["panel"], fg=t["muted"], font=("Segoe UI", 8), wraplength=700, justify="left").pack(
                 anchor="w", padx=16, pady=(0, 6))
        ttk.Checkbutton(block_frame, text="Enable local firewall blocking action",
                         variable=self.enable_blocking).pack(anchor="w", padx=16, pady=(0, 12))

    def _on_simulation_mode_changed(self):
        sim = self.simulation_mode.get()
        if hasattr(self, "iface_combo"):
            try:
                self.iface_combo.configure(state="disabled" if sim else "readonly")
            except tk.TclError:
                pass
        if hasattr(self, "start_btn"):
            self.start_btn.configure(
                text=("\u25B6  Start Simulation" if sim else "\u25B6  Start Monitoring"))

    def _trigger_demo_scenario(self, name):
        if not self.simulation_mode.get():
            messagebox.showinfo("Simulation Mode Required",
                                 "Turn on 'Use Simulated Traffic Generator' above first.")
            return
        if not self.simulator.running:
            messagebox.showinfo("Start Monitoring First",
                                 "Click Start Monitoring in the sidebar first, then trigger a demo attack.")
            return
        self.simulator.trigger_scenario(name)

    def _format_thresholds(self):
        c = self.config
        lines = [
            f"Port Scan:            {c['port_scan']['port_threshold']} ports / {c['port_scan']['time_window_seconds']}s",
            f"ICMP Flood:           {c['icmp_flood']['packet_threshold']} pkts / {c['icmp_flood']['time_window_seconds']}s",
            f"TCP SYN Flood:        {c['syn_flood']['packet_threshold']} pkts / {c['syn_flood']['time_window_seconds']}s",
            f"High Packet Rate:     {c['high_packet_rate']['packet_threshold']} pkts / {c['high_packet_rate']['time_window_seconds']}s",
            f"Repeated Connections: {c['repeated_connection']['attempt_threshold']} attempts / {c['repeated_connection']['time_window_seconds']}s",
            f"Suspicious Ports:     {', '.join(str(p) for p in c.get('suspicious_ports', []))}",
        ]
        return "\n".join(lines)

    def _refresh_interfaces(self):
        interfaces = self.capture.list_interfaces()
        self.iface_map = {"Default (let OS choose)": None}
        for display, iface_id in interfaces:
            self.iface_map[display] = iface_id
        self.iface_combo["values"] = list(self.iface_map.keys())
        if self.selected_iface_display.get() not in self.iface_map:
            self.selected_iface_display.set("Default (let OS choose)")

    # ==================================================================== #
    # Navigation
    # ==================================================================== #

    def _show_frame(self, key):
        self.current_frame_key = key
        t = self.theme
        for k, frame in self.frames.items():
            frame.pack_forget()
        self.frames[key].pack(fill="both", expand=True)
        for k, btn in self.nav_buttons.items():
            active = (k == key)
            btn.configure(fg=self.accent if active else t["text"], bg=t["panel_alt"] if active else t["sidebar"])
            self.nav_indicators[k].configure(bg=self.accent if active else t["sidebar"])

    # ==================================================================== #
    # Accent color theme switching
    # ==================================================================== #

    def _change_accent(self):
        name = self.accent_choice.get()
        self.accent = utils.ACCENT_PRESETS.get(name, DEFAULT_ACCENT)
        self._apply_accent()

    def _apply_accent(self):
        t = self.theme
        self.title_label.configure(fg=self.accent)
        self.start_btn.configure(bg=self.accent)
        if self.capture.running:
            self.status_label.configure(fg=self.accent)
        for k, btn in self.nav_buttons.items():
            active = (k == self.current_frame_key)
            btn.configure(fg=self.accent if active else t["text"], activeforeground=self.accent)
            self.nav_indicators[k].configure(bg=self.accent if active else t["sidebar"])
        style = ttk.Style()
        style.map("Treeview", background=[("selected", self.accent)])
        if hasattr(self, "stat_cards"):
            self.stat_cards["total_packets"].set_color(self.accent)

    # ==================================================================== #
    # Monitoring control
    # ==================================================================== #

    def _start_monitoring(self):
        if self.capture.running or self.simulator.running:
            return

        if self.simulation_mode.get():
            self.active_source = self.simulator
            try:
                self.simulator.start()
            except Exception as e:
                messagebox.showerror("Simulation Error", f"Could not start traffic simulator:\n{e}")
                return
            status_text = "\u25CF LIVE (Simulated)"
            self.logger.log_info("Monitoring started using the synthetic traffic simulator.")
        else:
            self.active_source = self.capture
            iface_id = self.iface_map.get(self.selected_iface_display.get())
            try:
                self.capture.start(interface=iface_id)
            except Exception as e:
                messagebox.showerror("Capture Error", f"Could not start capture:\n{e}")
                return
            status_text = "\u25CF LIVE"
            self.logger.log_info(f"Monitoring started on interface: {iface_id or 'default'}")

        self.session_start_time = time.time()
        self.status_label.configure(text=status_text, fg=self.accent)
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        if hasattr(self, "data_source_badge"):
            self.data_source_badge.configure(
                text="\u26A0 SIMULATED DATA" if self.simulation_mode.get() else "")

    def _stop_monitoring(self):
        if self.active_source is not None:
            self.active_source.stop()
        self.active_source = None
        self.status_label.configure(text="\u25CF STOPPED", fg=self.theme["danger"])
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if hasattr(self, "data_source_badge"):
            self.data_source_badge.configure(text="")
        self.logger.log_info("Monitoring stopped.")

    def _refresh_firewall_button(self):
        """
        Read-only poll of the LOCAL machine's actual Windows Firewall state
        and reflect it on the sidebar button. Never changes anything.
        """
        t = self.theme
        state = utils.get_firewall_state()
        if state == "ON":
            self.firewall_btn.configure(text="\U0001F6E1  Firewall: ON", fg=t["ok"])
        elif state == "OFF":
            self.firewall_btn.configure(text="\U0001F6E1  Firewall: OFF", fg=t["danger"])
        elif state == "MIXED":
            self.firewall_btn.configure(text="\U0001F6E1  Firewall: MIXED", fg=t["warn"])
        else:
            self.firewall_btn.configure(text="\U0001F6E1  Firewall: N/A", fg=t["muted"])
        self.root.after(5000, self._refresh_firewall_button)

    def _toggle_firewall(self):
        """
        Direct, user-clicked action that connects to this PC's own Windows
        Firewall and switches it ON/OFF (all profiles). Local-machine only -
        never touches any remote host. Always confirmed before running.
        """
        current = utils.get_firewall_state()
        if current == "ON":
            target, verb = False, "turn OFF"
        else:
            target, verb = True, "turn ON"

        confirmed = messagebox.askyesno(
            "Confirm Firewall Change",
            f"This will directly connect to this PC's Windows Firewall settings and "
            f"{verb} it for all profiles (Domain/Private/Public).\n\n"
            "This only changes your own computer's firewall - it never sends any "
            "traffic to a remote host.\n\nContinue?",
        )
        if not confirmed:
            return

        ok, message = utils.set_firewall_state(target)
        if ok:
            messagebox.showinfo("Firewall Updated", message)
            if hasattr(self, "logger"):
                self.logger.log_info(f"User {verb} the local Windows Firewall via dashboard button.")
        else:
            messagebox.showerror("Firewall Change Failed", message)
        self._refresh_firewall_button()

    def _tick_uptime(self):
        is_running = self.capture.running or self.simulator.running
        if is_running and self.session_start_time:
            elapsed = int(time.time() - self.session_start_time)
            h, rem = divmod(elapsed, 3600)
            m, s = divmod(rem, 60)
            self.uptime_label.configure(text=f"Uptime: {h:02d}:{m:02d}:{s:02d}")
        self.root.after(1000, self._tick_uptime)

    # ==================================================================== #
    # Callbacks from the capture thread (thread-safe: queue puts only)
    # ==================================================================== #

    def _on_packet(self, packet_info):
        self.packet_queue.put(packet_info)
        try:
            alerts = self.detector.process_packet(packet_info)
            for alert in alerts:
                stored = self.alert_manager.add_alert(alert)
                if stored:
                    self.alert_queue.put(stored)
        except Exception as e:
            self.error_queue.put(f"Detector error: {e}")

    def _on_capture_error(self, message):
        self.error_queue.put(message)

    # ==================================================================== #
    # Main-thread queue draining (safe to touch widgets here)
    # ==================================================================== #

    def _poll_queues(self):
        try:
            while True:
                msg = self.error_queue.get_nowait()
                self._handle_capture_error(msg)
        except queue.Empty:
            pass

        processed = 0
        try:
            while processed < 300:
                pkt = self.packet_queue.get_nowait()
                self._handle_packet(pkt)
                processed += 1
        except queue.Empty:
            pass

        try:
            while True:
                alert = self.alert_queue.get_nowait()
                self._handle_alert(alert)
        except queue.Empty:
            pass

        self._update_stat_cards()

        refresh_ms = self.config.get("gui", {}).get("refresh_interval_ms", 200)
        self.root.after(refresh_ms, self._poll_queues)

    def _handle_capture_error(self, message):
        self._stop_monitoring()
        messagebox.showerror("Network Capture Error", message)
        self.logger.log_error(message)

    def _handle_packet(self, pkt):
        self.total_packets += 1
        self.total_bytes += pkt.get("length", 0) or 0
        self.unique_src_ips.add(pkt.get("src_ip"))
        self.protocol_counts[pkt.get("protocol", "OTHER")] += 1
        self.src_ip_counts[pkt.get("src_ip")] += 1
        self.packet_log.append(pkt)

        sec = int(pkt["timestamp"])
        self.bandwidth_buckets[sec] = self.bandwidth_buckets.get(sec, 0) + (pkt.get("length", 0) or 0)
        cutoff = sec - 90
        for k in [k for k in self.bandwidth_buckets if k < cutoff]:
            del self.bandwidth_buckets[k]

        self._maybe_display_packet(pkt)

    def _maybe_display_packet(self, pkt):
        if not self._passes_packet_filter(pkt):
            return
        row_id = self.packets_tree.insert("", "end", values=(
            utils.format_timestamp(pkt["timestamp"]),
            pkt.get("src_ip", ""),
            pkt.get("dst_ip", ""),
            pkt.get("protocol", ""),
            pkt.get("src_port") if pkt.get("src_port") is not None else "-",
            pkt.get("dst_port") if pkt.get("dst_port") is not None else "-",
            pkt.get("length", ""),
        ))
        self.packet_rows[row_id] = pkt
        self.displayed_packet_ids.append(row_id)
        if self.auto_scroll.get():
            self.packets_tree.see(row_id)
        if len(self.displayed_packet_ids) > self.max_display_packets:
            old = self.displayed_packet_ids.popleft()
            if self.packets_tree.exists(old):
                self.packets_tree.delete(old)
            self.packet_rows.pop(old, None)

    def _repopulate_packet_table(self):
        """Re-fill the (freshly rebuilt) packet table from the retained
        packet_log after a theme change, so recent traffic is still visible."""
        self.packet_rows.clear()
        self.displayed_packet_ids.clear()
        recent = list(self.packet_log)[-self.max_display_packets:]
        for pkt in recent:
            self._maybe_display_packet(pkt)

    def _passes_packet_filter(self, pkt):
        proto_filter = self.filter_protocol.get()
        if proto_filter != "All" and pkt.get("protocol") != proto_filter:
            return False
        src_filter = self.filter_src.get().strip()
        if src_filter and src_filter not in (pkt.get("src_ip") or ""):
            return False
        dst_filter = self.filter_dst.get().strip()
        if dst_filter and dst_filter not in (pkt.get("dst_ip") or ""):
            return False
        return True

    def _handle_alert(self, alert):
        self.total_alerts += 1
        self.severity_counts[alert["severity"]] += 1
        if alert["severity"] in ("High", "Critical"):
            self.high_severity_count += 1
        self.attack_type_counts[alert["attack_type"]] += 1
        self.alert_time_buckets.append(int(alert["timestamp"] // 60) * 60)
        self.all_alerts_list.append(alert)

        self.latest_alert = alert
        color = self._severity_color(alert["severity"])
        self.latest_alert_label.configure(
            text=f"[{alert['severity']}] {alert['attack_type']}\n"
                 f"{alert['src_ip']} -> {alert['dst_ip']}\n{alert['reason']}",
            fg=color
        )

        if alert["severity"] == "Critical" and self.sound_alerts.get():
            utils.beep_alert()

        if self._alert_passes_filter(alert):
            self._insert_alert_row(alert, index=0)

    def _insert_alert_row(self, alert, index="end"):
        self.alerts_tree.insert("", index, values=(
            alert["datetime"], alert["src_ip"], alert["dst_ip"],
            alert["attack_type"], alert["severity"], alert["reason"],
        ), tags=(alert["severity"],))

    def _alert_passes_filter(self, alert):
        sev = self.alert_severity_filter.get()
        if sev != "All" and alert["severity"] != sev:
            return False
        query = self.alert_search.get().strip().lower()
        if query:
            hay = f"{alert['src_ip']} {alert['dst_ip']} {alert['attack_type']} {alert['reason']}".lower()
            if query not in hay:
                return False
        return True

    def _render_alerts_from_filter(self):
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        for alert in reversed(self.all_alerts_list):
            if self._alert_passes_filter(alert):
                self._insert_alert_row(alert, index="end")

    def _update_stat_cards(self):
        self.stat_cards["total_packets"].set_value(f"{self.total_packets:,}")
        self.stat_cards["total_bytes"].set_value(self._format_bytes(self.total_bytes))
        self.stat_cards["total_alerts"].set_value(f"{self.total_alerts:,}")
        self.stat_cards["high_severity"].set_value(f"{self.high_severity_count:,}")
        self.stat_cards["unique_ips"].set_value(f"{len(self.unique_src_ips):,}")
        self.health_gauge.set_score(self._compute_health_score())

    @staticmethod
    def _format_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    def _compute_health_score(self):
        crit = self.severity_counts.get("Critical", 0)
        high = self.severity_counts.get("High", 0)
        med = self.severity_counts.get("Medium", 0)
        low = self.severity_counts.get("Low", 0)
        penalty = crit * 8 + high * 4 + med * 1.5 + low * 0.5
        return max(0, 100 - penalty)

    # ==================================================================== #
    # Charts
    # ==================================================================== #

    def _refresh_charts(self):
        self._draw_charts_only()
        chart_ms = self.config.get("gui", {}).get("chart_refresh_ms", 1500)
        self.root.after(chart_ms, self._refresh_charts)

    def _draw_charts_only(self):
        t = self.theme
        try:
            self.ax_attack.clear()
            self.ax_attack.set_title("Attack Type Distribution", color=t["text"], fontsize=9)
            if self.attack_type_counts:
                labels = list(self.attack_type_counts.keys())
                values = [self.attack_type_counts[k] for k in labels]
                self.ax_attack.bar(range(len(labels)), values, color=self.accent)
                self.ax_attack.set_xticks(range(len(labels)))
                self.ax_attack.set_xticklabels(labels, rotation=30, ha="right", fontsize=6, color=t["muted"])

            self.ax_proto.clear()
            self.ax_proto.set_title("Protocol Distribution", color=t["text"], fontsize=9)
            if self.protocol_counts:
                labels = list(self.protocol_counts.keys())
                values = [self.protocol_counts[k] for k in labels]
                colors = [self.accent, "#3b82f6", t["warn"], "#9b59b6", t["high"]]
                self.ax_proto.pie(values, labels=labels, autopct="%1.0f%%",
                                   textprops={"color": t["text"], "fontsize": 7},
                                   colors=colors[:len(labels)])

            self.ax_time.clear()
            self.ax_time.set_title("Alerts Over Time", color=t["text"], fontsize=9)
            if self.alert_time_buckets:
                counts = Counter(self.alert_time_buckets)
                buckets = sorted(counts.keys())
                values = [counts[b] for b in buckets]
                labels = [time.strftime("%H:%M", time.localtime(b)) for b in buckets]
                self.ax_time.plot(range(len(values)), values, color=t["danger"], marker="o", markersize=3)
                step = max(1, len(labels) // 6)
                self.ax_time.set_xticks(range(0, len(labels), step))
                self.ax_time.set_xticklabels(labels[::step], rotation=30, ha="right", fontsize=6, color=t["muted"])

            self.ax_bw.clear()
            self.ax_bw.set_title("Bandwidth (KB/s)", color=t["text"], fontsize=9)
            if self.bandwidth_buckets:
                buckets = sorted(self.bandwidth_buckets.keys())
                values = [self.bandwidth_buckets[b] / 1024.0 for b in buckets]
                labels = [time.strftime("%H:%M:%S", time.localtime(b)) for b in buckets]
                self.ax_bw.plot(range(len(values)), values, color=self.accent, linewidth=1.5)
                self.ax_bw.fill_between(range(len(values)), values, color=self.accent, alpha=0.15)
                step = max(1, len(labels) // 5)
                self.ax_bw.set_xticks(range(0, len(labels), step))
                self.ax_bw.set_xticklabels(labels[::step], rotation=30, ha="right", fontsize=6, color=t["muted"])

            for ax in (self.ax_attack, self.ax_proto, self.ax_time, self.ax_bw):
                ax.set_facecolor(t["panel_alt"])
                for spine in ax.spines.values():
                    spine.set_color(t["border"])

            self.fig.patch.set_facecolor(t["bg"])
            self._refresh_top_talkers()

            self.fig.tight_layout()
            self.canvas.draw_idle()
        except Exception as e:
            self.logger.log_error(f"Chart refresh error: {e}")

    def _refresh_top_talkers(self):
        self.talkers_tree.delete(*self.talkers_tree.get_children())
        total = max(1, self.total_packets)
        for rank, (ip, count) in enumerate(self.src_ip_counts.most_common(5), start=1):
            pct = (count / total) * 100
            self.talkers_tree.insert("", "end", values=(rank, ip, f"{count:,}", f"{pct:.1f}%"))

    # ==================================================================== #
    # Sorting / detail popup
    # ==================================================================== #

    def _sort_by_column(self, tree, col, descending):
        data = [(tree.set(k, col), k) for k in tree.get_children("")]

        def convert(v):
            try:
                return float(str(v).replace(",", "").replace("%", ""))
            except ValueError:
                return str(v).lower()

        data.sort(key=lambda t: convert(t[0]), reverse=descending)
        for index, (_, k) in enumerate(data):
            tree.move(k, "", index)
        tree.heading(col, command=lambda: self._sort_by_column(tree, col, not descending))

    def _show_packet_detail(self, event):
        sel = self.packets_tree.selection()
        if not sel:
            return
        pkt = self.packet_rows.get(sel[0])
        if not pkt:
            return

        t = self.theme
        top = tk.Toplevel(self.root)
        top.title("Packet Details")
        top.configure(bg=t["panel"])
        top.geometry("400x320")
        top.resizable(False, False)

        tk.Label(top, text="Packet Details", bg=t["panel"], fg=self.accent,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=16, pady=(14, 6))

        friendly = {
            "timestamp": "Timestamp", "src_ip": "Source IP", "dst_ip": "Destination IP",
            "protocol": "Protocol", "src_port": "Source Port", "dst_port": "Destination Port",
            "length": "Length (bytes)", "tcp_flags": "TCP Flags", "icmp_type": "ICMP Type",
        }
        for key, label in friendly.items():
            if key not in pkt or pkt[key] is None:
                continue
            value = utils.format_timestamp(pkt[key]) if key == "timestamp" else pkt[key]
            row = tk.Frame(top, bg=t["panel"])
            row.pack(fill="x", padx=16, pady=3)
            tk.Label(row, text=f"{label}:", bg=t["panel"], fg=t["muted"], font=("Segoe UI", 9),
                     width=16, anchor="w").pack(side="left")
            tk.Label(row, text=str(value), bg=t["panel"], fg=t["text"], font=("Consolas", 9),
                     anchor="w").pack(side="left")

        tk.Button(top, text="Close", command=top.destroy, bg=t["panel_alt"], fg=t["text"],
                  relief="flat", padx=12, pady=4, cursor="hand2").pack(pady=14)

    # ==================================================================== #
    # Alert actions
    # ==================================================================== #

    def _clear_alerts(self):
        if not messagebox.askyesno("Clear Alerts", "Clear all displayed alerts? The saved log file is not affected."):
            return
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        self.alert_manager.clear_alerts()
        self.all_alerts_list.clear()
        self.total_alerts = 0
        self.high_severity_count = 0
        self.severity_counts.clear()
        self.attack_type_counts.clear()
        self.alert_time_buckets.clear()
        self.latest_alert = None
        self.latest_alert_label.configure(text="No alerts yet.", fg=self.theme["muted"])

    def _export_alerts_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="alerts_export.csv",
        )
        if not path:
            return
        ok = self.alert_manager.export_csv(path)
        if ok:
            messagebox.showinfo("Export Complete", f"Alerts exported to:\n{path}")
        else:
            messagebox.showwarning("Nothing to Export", "There are no alerts to export yet.")

    def _export_packets_csv(self):
        if not self.packet_log:
            messagebox.showwarning("Nothing to Export", "No packets have been captured yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="packets_export.csv",
        )
        if not path:
            return
        import csv
        fieldnames = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "length"]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for pkt in self.packet_log:
                    row = {k: pkt.get(k, "") for k in fieldnames}
                    row["timestamp"] = utils.format_timestamp(pkt["timestamp"])
                    writer.writerow(row)
            messagebox.showinfo("Export Complete", f"Packets exported to:\n{path}\n"
                                                     f"(most recent {len(self.packet_log):,} packets)")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export packets:\n{e}")

    def _block_selected(self):
        selection = self.alerts_tree.selection()
        if not selection:
            messagebox.showinfo("Block Source", "Select an alert row first to identify the source IP.")
            return
        values = self.alerts_tree.item(selection[0], "values")
        src_ip = values[1]

        if not self.enable_blocking.get():
            messagebox.showinfo(
                "Blocking Disabled",
                "The local firewall blocking action is disabled by default.\n\n"
                "Enable it in Settings first if you want to use this feature."
            )
            return

        if not messagebox.askyesno(
            "Confirm Local Firewall Block",
            f"Add a Windows Firewall rule blocking inbound/outbound traffic "
            f"to/from {src_ip} on this machine?\n\n"
            "This only changes your own computer's firewall - it does not "
            "contact or affect the remote host in any way."
        ):
            return

        ok, message = utils.block_ip_windows(src_ip)
        if ok:
            messagebox.showinfo("Blocked", message)
            self.logger.log_info(f"User blocked source IP via local firewall: {src_ip}")
        else:
            messagebox.showerror("Block Failed", message)

    # ==================================================================== #
    # Session report
    # ==================================================================== #

    def _generate_report(self):
        duration = int(time.time() - self.session_start_time) if self.session_start_time else 0
        report = {
            "generated_at": utils.format_timestamp(time.time()),
            "monitoring_duration_seconds": duration,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_alerts": self.total_alerts,
            "high_severity_alerts": self.high_severity_count,
            "network_health_score": self._compute_health_score(),
            "unique_source_ips": len(self.unique_src_ips),
            "severity_breakdown": dict(self.severity_counts),
            "attack_type_breakdown": dict(self.attack_type_counts),
            "protocol_breakdown": dict(self.protocol_counts),
            "top_talkers": [
                {"src_ip": ip, "packets": count}
                for ip, count in self.src_ip_counts.most_common(5)
            ],
        }

        ts = time.strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(self.data_dir, f"session_report_{ts}.json")
        txt_path = os.path.join(self.data_dir, f"session_report_{ts}.txt")

        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            lines = [
                "PROFESSIONAL NIDS - SESSION REPORT",
                f"Generated: {report['generated_at']}",
                f"Monitoring duration: {duration}s",
                "",
                f"Total Packets: {report['total_packets']:,}",
                f"Data Captured: {self._format_bytes(report['total_bytes'])}",
                f"Total Alerts: {report['total_alerts']}",
                f"High/Critical Alerts: {report['high_severity_alerts']}",
                f"Network Health Score: {report['network_health_score']}/100",
                f"Unique Source IPs: {report['unique_source_ips']}",
                "",
                "Severity Breakdown: " + str(report["severity_breakdown"]),
                "Attack Type Breakdown: " + str(report["attack_type_breakdown"]),
                "Protocol Breakdown: " + str(report["protocol_breakdown"]),
                "",
                "Top Talkers:",
            ]
            for tk_ in report["top_talkers"]:
                lines.append(f"  - {tk_['src_ip']}: {tk_['packets']} packets")

            with open(txt_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))

            messagebox.showinfo("Report Generated", f"Session report saved to:\n{json_path}\n{txt_path}")
        except Exception as e:
            messagebox.showerror("Report Failed", f"Could not generate report:\n{e}")

    # ==================================================================== #

    def _on_close(self):
        try:
            if self.capture.running:
                self.capture.stop()
            if self.simulator.running:
                self.simulator.stop()
        finally:
            self.root.destroy()
