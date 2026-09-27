"""
alert_manager.py
Owns the in-memory list of alerts, de-duplicates near-identical repeated
alerts (so a single ongoing attack does not spam thousands of identical
rows), and provides CSV export.
"""

import csv
from threading import Lock


class AlertManager:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.alerts = []
        self._last_alert_time = {}
        self._lock = Lock()
        self._next_id = 1

    def add_alert(self, alert):
        """
        Add an alert unless an alert of the same (src_ip, attack_type) was
        already raised within the configured dedup window. Returns the
        stored alert dict (with an 'id' assigned) or None if it was
        suppressed as a duplicate.
        """
        dedup_key = (alert["src_ip"], alert["attack_type"])
        now = alert["timestamp"]
        dedup_seconds = self.config.get("alert_dedup_seconds", 30)

        with self._lock:
            last = self._last_alert_time.get(dedup_key)
            if last is not None and (now - last) < dedup_seconds:
                return None

            self._last_alert_time[dedup_key] = now
            alert = dict(alert)
            alert["id"] = self._next_id
            self._next_id += 1
            self.alerts.append(alert)

        self.logger.log_alert(alert)
        return alert

    def clear_alerts(self):
        """Clear the displayed/in-memory alert list (the JSON log file is untouched)."""
        with self._lock:
            self.alerts.clear()

    def get_alerts(self):
        with self._lock:
            return list(self.alerts)

    def export_csv(self, filepath):
        with self._lock:
            alerts_copy = list(self.alerts)

        if not alerts_copy:
            return False

        fieldnames = ["id", "datetime", "src_ip", "dst_ip", "attack_type", "severity", "reason"]
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for a in alerts_copy:
                writer.writerow({k: a.get(k, "") for k in fieldnames})
        return True
