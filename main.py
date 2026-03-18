"""
main.py
-------
AI-NIDS Orchestrator.

Wires together:
  PacketCapture → IntrusionDetector → AlertSystem → FirewallManager → Dashboard

Usage:
    sudo python main.py                  # live capture (requires root + Scapy)
    python main.py --simulate            # simulation mode (no root needed)
    python main.py --help
"""

import sys
import os
import queue
import logging
import argparse
import threading
import time
from datetime import datetime

# ── Path setup (allow running from project root) ──────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

# ── Module imports ────────────────────────────────────────────────────────────
from network.packet_capture import PacketCapture
from detection.intrusion_detection import IntrusionDetector
from alerts.alert_system import AlertSystem
from security.firewall import FirewallManager
import dashboard.app as dashboard_app

# ── Logging configuration ─────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/nids.log"),
    ],
)
logger = logging.getLogger("main")


# ── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "model_dir":       "model/",
    "log_file":        "logs/alerts.jsonl",
    "dashboard_host":  "0.0.0.0",
    "dashboard_port":  5000,
    "enable_email":    False,
    "enable_firewall": True,
    "whitelist_ips":   ["127.0.0.1", "::1"],
    "bpf_filter":      "ip",           # BPF filter for Scapy
    "interface":       None,           # None → auto-detect
    "simulate":        False,
    # Email settings (populate or use env vars)
    "email_config": {
        # "smtp_host": "smtp.gmail.com",
        # "smtp_port": 587,
        # "smtp_user": "your@gmail.com",
        # "smtp_pass": "app-password",
        # "recipient": "admin@example.com",
    },
}


# ── Detection worker ──────────────────────────────────────────────────────────

class DetectionPipeline:
    """
    Runs in its own thread.
    Drains the packet queue and runs: detect → alert → firewall → dashboard.
    """

    def __init__(self, packet_queue: queue.Queue, config: dict):
        self.packet_queue = packet_queue
        self.config = config
        self._stop = threading.Event()

        logger.info("Loading intrusion detection model …")
        self.detector = IntrusionDetector(model_dir=config["model_dir"])

        self.alerter = AlertSystem(
            log_file=config["log_file"],
            email_config=config.get("email_config"),
            enable_email=config["enable_email"],
        )

        self.firewall = FirewallManager(
            enabled=config["enable_firewall"],
            whitelist=config["whitelist_ips"],
        )

    def run(self):
        logger.info("Detection pipeline started.")
        while not self._stop.is_set():
            try:
                packet_features = self.packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            # 1. Detect
            result = self.detector.detect(packet_features)

            # 2. Alert
            self.alerter.process(result)

            # 3. Firewall (auto-block)
            blocked = self.firewall.maybe_block(result)
            if blocked:
                result.blocked = True

            # 4. Dashboard
            dashboard_app.push_result(result.to_dict())

    def stop(self):
        self._stop.set()


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="AI-NIDS – Intrusion Detection System")
    p.add_argument("--simulate", action="store_true",
                   help="Run in simulation mode (no Scapy / root needed)")
    p.add_argument("--interface", default=None,
                   help="Network interface to sniff (default: auto)")
    p.add_argument("--port", type=int, default=5000,
                   help="Dashboard port (default: 5000)")
    p.add_argument("--no-firewall", action="store_true",
                   help="Disable automatic IP blocking")
    p.add_argument("--model-dir", default="model/",
                   help="Path to model directory")
    return p.parse_args()


def main():
    args = parse_args()

    config = {**DEFAULT_CONFIG}
    config["simulate"]        = args.simulate
    config["interface"]       = args.interface
    config["dashboard_port"]  = args.port
    config["enable_firewall"] = not args.no_firewall
    config["model_dir"]       = args.model_dir

    logger.info("=" * 60)
    logger.info("  AI-Enhanced Network Intrusion Detection System")
    logger.info(f"  Mode     : {'SIMULATION' if config['simulate'] else 'LIVE CAPTURE'}")
    logger.info(f"  Dashboard: http://localhost:{config['dashboard_port']}")
    logger.info(f"  Model    : {config['model_dir']}")
    logger.info(f"  Firewall : {'ENABLED' if config['enable_firewall'] else 'DISABLED'}")
    logger.info("=" * 60)

    # Shared packet queue between capture and detection threads
    packet_queue: queue.Queue = queue.Queue(maxsize=2000)

    # ── Start packet capture ──────────────────────────────────────────────────
    capture = PacketCapture(
        packet_queue=packet_queue,
        interface=config["interface"],
        bpf_filter=config["bpf_filter"],
    )

    if config["simulate"]:
        # Force simulation mode
        from unittest.mock import patch
        with patch("network.packet_capture.SCAPY_AVAILABLE", False):
            capture.start()
    else:
        capture.start()

    # ── Start detection pipeline ──────────────────────────────────────────────
    pipeline = DetectionPipeline(packet_queue, config)
    pipeline_thread = threading.Thread(target=pipeline.run, daemon=True)
    pipeline_thread.start()

    # ── Start dashboard (blocking – runs the Flask dev server) ───────────────
    try:
        dashboard_app.run_dashboard(
            host=config["dashboard_host"],
            port=config["dashboard_port"],
            debug=False,
        )
    except KeyboardInterrupt:
        logger.info("\nShutdown requested …")
    finally:
        pipeline.stop()
        capture.stop()
        stats = pipeline.alerter.stats()
        logger.info(
            f"Session summary – "
            f"Packets: {stats['total_alerts']}, "
            f"Attacks: {stats['total_attacks']}"
        )
        logger.info("AI-NIDS stopped.")


if __name__ == "__main__":
    main()
