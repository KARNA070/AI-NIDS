"""
firewall.py
-----------
Automatically blocks malicious IPs using Windows Firewall (netsh).
Maintains a set of already-blocked IPs to avoid duplicate rules.
Only triggers for HIGH / CRITICAL severity events.
"""

import subprocess
import logging
import os
import json
import time
from typing import Set
from datetime import datetime

logger = logging.getLogger(__name__)

# Severity levels that trigger auto-blocking
BLOCK_SEVERITIES = {"HIGH", "CRITICAL"}

# File to persist blocked IPs across restarts
BLOCKED_IPS_FILE = "logs/blocked_ips.json"


class FirewallManager:
    """
    Manages IP blocking via iptables.

    On non-Linux systems (or without root), operates in DRY-RUN mode
    – it logs what it *would* do without actually running iptables.
    """

    def __init__(
        self,
        enabled: bool = True,
        dry_run: bool = False,
        whitelist: list = None,
    ):
        self._blocked: Set[str] = set()
        self._block_log: list = []
        self.enabled = enabled
        self.whitelist: Set[str] = set(whitelist or [])

        # Auto-detect if firewall is available
        self.dry_run = dry_run or not self._firewall_available()

        if self.dry_run:
            logger.warning(
                "FirewallManager running in DRY-RUN mode "
                "(Windows Firewall unavailable or no admin privileges)."
            )

        self._load_blocked_ips()

    # ── Public API ────────────────────────────────────────────────────────────

    def maybe_block(self, detection_result) -> bool:
        """
        Block source IP if result severity warrants it.
        Returns True if the IP was (or already was) blocked.
        """
        if not self.enabled:
            return False
        if detection_result.severity not in BLOCK_SEVERITIES:
            return False

        ip = detection_result.src_ip
        return self.block_ip(ip, reason=detection_result.attack_type)

    def block_ip(self, ip: str, reason: str = "Manual") -> bool:
        """Block a specific IP. Returns True if action was taken."""
        if ip in self.whitelist:
            logger.info(f"IP {ip} is whitelisted – not blocking.")
            return False

        if ip in self._blocked:
            return True  # already blocked

        success = self._run_firewall_cmd("block", ip)
        if success:
            self._blocked.add(ip)
            entry = {
                "ip": ip,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat(),
                "dry_run": self.dry_run,
            }
            self._block_log.append(entry)
            self._save_blocked_ips()
            logger.info(f"{'[DRY-RUN] ' if self.dry_run else ''}Blocked IP: {ip} ({reason})")
        return success

    def unblock_ip(self, ip: str) -> bool:
        """Remove DROP rule for an IP."""
        if ip not in self._blocked:
            logger.info(f"IP {ip} is not in blocked list.")
            return False
        success = self._run_firewall_cmd("block", ip, delete=True)
        if success:
            self._blocked.discard(ip)
            self._save_blocked_ips()
            logger.info(f"Unblocked IP: {ip}")
        return success

    @property
    def blocked_ips(self) -> list:
        return list(self._blocked)

    def block_log(self) -> list:
        return list(self._block_log)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _run_firewall_cmd(self, action: str, ip: str, delete: bool = False) -> bool:
        """Execute a netsh advfirewall command. Returns True on success."""
        rule_name = f"AI-NIDS Block {ip}"
        if delete:
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        else:
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {' '.join(cmd)}")
            return True

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 or "No rules match the specified criteria" in result.stdout:
                return True
            logger.error(f"netsh error: {result.stdout.strip()} {result.stderr.strip()}")
            return False
        except FileNotFoundError:
            logger.error("netsh binary not found.")
            return False
        except subprocess.TimeoutExpired:
            logger.error("netsh command timed out.")
            return False
        except PermissionError:
            logger.error("Insufficient privileges to run netsh.")
            return False

    @staticmethod
    def _firewall_available() -> bool:
        """Check if we have netsh and admin root."""
        if os.name != "nt":
            return False
        try:
            # Running this requires admin privileges to write, but to read we can do 'show'
            # Let's see if we can read profiles.
            r = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile"],
                capture_output=True, timeout=3
            )
            return r.returncode == 0
        except Exception:
            return False

    def _save_blocked_ips(self):
        os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
        try:
            with open(BLOCKED_IPS_FILE, "w") as f:
                json.dump({"blocked": list(self._blocked), "log": self._block_log}, f, indent=2)
        except OSError as e:
            logger.error(f"Could not save blocked IPs: {e}")

    def _load_blocked_ips(self):
        if not os.path.exists(BLOCKED_IPS_FILE):
            return
        try:
            with open(BLOCKED_IPS_FILE) as f:
                data = json.load(f)
            self._blocked = set(data.get("blocked", []))
            self._block_log = data.get("log", [])
            if self._blocked:
                logger.info(f"Restored {len(self._blocked)} previously blocked IPs.")
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Could not load blocked IPs: {e}")
