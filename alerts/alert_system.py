"""
alert_system.py
---------------
Handles console printing, file logging, and routing to email alerts.
Each alert is assigned a severity; only HIGH / CRITICAL trigger email.
"""

import logging
import os
import json
import time
from datetime import datetime
from typing import Optional

from alerts.email_alert import EmailAlerter

logger = logging.getLogger(__name__)

# Severity levels that trigger an email
EMAIL_TRIGGER_SEVERITIES = {"HIGH", "CRITICAL"}

# ANSI colours for console output
COLOURS = {
    "INFO":     "\033[92m",
    "LOW":      "\033[96m",
    "MEDIUM":   "\033[93m",
    "HIGH":     "\033[91m",
    "CRITICAL": "\033[95m\033[1m",
}
RESET = "\033[0m"


class AlertSystem:
    """
    Central alert dispatcher.
    - Prints coloured alerts to the console.
    - Appends structured JSON lines to a log file.
    - Optionally triggers email for high-severity events.
    """

    def __init__(
        self,
        log_file: str = "logs/alerts.jsonl",
        email_config: Optional[dict] = None,
        enable_email: bool = False,
    ):
        self.log_file = log_file
        self.enable_email = enable_email
        self._email_alerter: Optional[EmailAlerter] = None
        self._alert_count = 0
        self._attack_count = 0

        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        if enable_email and email_config:
            try:
                self._email_alerter = EmailAlerter(**email_config)
                logger.info("Email alerter initialised.")
            except Exception as e:
                logger.warning(f"Email alerter failed to initialise: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, detection_result) -> None:
        """
        Main entry point: receive a DetectionResult, dispatch alerts.
        """
        self._alert_count += 1

        if detection_result.attack_type != "Normal":
            self._attack_count += 1

        self._console_alert(detection_result)
        self._log_to_file(detection_result)

        if (self.enable_email and
                detection_result.severity in EMAIL_TRIGGER_SEVERITIES and
                self._email_alerter):
            self._send_email(detection_result)

    # ── Console output ────────────────────────────────────────────────────────

    def _console_alert(self, result) -> None:
        colour = COLOURS.get(result.severity, "")
        ts = datetime.fromtimestamp(result.timestamp).strftime("%H:%M:%S")
        icon = {
            "Normal":    "✅",
            "DoS":       "🔥",
            "PortScan":  "🔍",
            "BruteForce":"🔑",
            "Exploit":   "💀",
        }.get(result.attack_type, "⚠️")

        line = (
            f"{colour}[{ts}] {icon} {result.severity:8s} | "
            f"{result.attack_type:12s} | "
            f"src={result.src_ip:<15s} dst={result.dst_ip:<15s} "
            f"proto={result.protocol:<5s} conf={result.confidence*100:.1f}%"
            f"{RESET}"
        )
        print(line)

    # ── File logging ──────────────────────────────────────────────────────────

    def _log_to_file(self, result) -> None:
        record = {
            "timestamp": datetime.fromtimestamp(result.timestamp).isoformat(),
            "src_ip":      result.src_ip,
            "dst_ip":      result.dst_ip,
            "protocol":    result.protocol,
            "service":     result.service,
            "attack_type": result.attack_type,
            "severity":    result.severity,
            "confidence":  round(result.confidence * 100, 1),
            "blocked":     result.blocked,
        }
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as e:
            logger.error(f"Failed to write alert log: {e}")

    # ── Email dispatch ────────────────────────────────────────────────────────

    def _send_email(self, result) -> None:
        subject = f"[NIDS ALERT] {result.severity} – {result.attack_type} from {result.src_ip}"
        body = (
            f"INTRUSION DETECTION ALERT\n"
            f"{'=' * 40}\n"
            f"Time       : {datetime.fromtimestamp(result.timestamp).isoformat()}\n"
            f"Attack Type: {result.attack_type}\n"
            f"Severity   : {result.severity}\n"
            f"Source IP  : {result.src_ip}\n"
            f"Dest IP    : {result.dst_ip}\n"
            f"Protocol   : {result.protocol}\n"
            f"Service    : {result.service}\n"
            f"Confidence : {result.confidence * 100:.1f}%\n"
            f"Blocked    : {'Yes' if result.blocked else 'No'}\n"
        )
        try:
            self._email_alerter.send(subject=subject, body=body)
            logger.info(f"Email alert sent for {result.attack_type} from {result.src_ip}")
        except Exception as e:
            logger.error(f"Email send failed: {e}")

    # ── Statistics ────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "total_alerts": self._alert_count,
            "total_attacks": self._attack_count,
        }
