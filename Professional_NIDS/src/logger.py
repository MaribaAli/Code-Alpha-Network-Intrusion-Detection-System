"""
logger.py
Handles persistent logging:
 - logs/activity.log   : human-readable running log via the logging module
 - logs/alerts_log.json: every alert ever raised, as a JSON array
"""

import json
import os
import logging


class Logger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        self.alert_json_path = os.path.join(log_dir, "alerts_log.json")
        self.activity_log_path = os.path.join(log_dir, "activity.log")

        self._logger = logging.getLogger("NIDS")
        self._logger.setLevel(logging.INFO)
        if not self._logger.handlers:
            handler = logging.FileHandler(self.activity_log_path, encoding="utf-8")
            handler.setFormatter(logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            ))
            self._logger.addHandler(handler)

        if not os.path.exists(self.alert_json_path):
            with open(self.alert_json_path, "w", encoding="utf-8") as f:
                json.dump([], f)

    def log_alert(self, alert):
        """Append one alert dict to the persistent JSON alert log."""
        try:
            with open(self.alert_json_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
        except FileNotFoundError:
            data = []

        data.append(alert)

        try:
            with open(self.alert_json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self._logger.error(f"Failed to persist alert to JSON log: {e}")

        self._logger.warning(
            f"ALERT [{alert.get('severity')}] {alert.get('attack_type')} "
            f"from {alert.get('src_ip')} -> {alert.get('dst_ip')}: {alert.get('reason')}"
        )

    def log_info(self, message):
        self._logger.info(message)

    def log_error(self, message):
        self._logger.error(message)
