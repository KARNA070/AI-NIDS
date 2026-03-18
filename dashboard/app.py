"""
app.py
------
Flask + Socket.IO dashboard for real-time NIDS monitoring.
Receives detection results via a thread-safe queue and pushes them
to connected browsers via WebSocket events.
"""

import os
import json
import time
import queue
import logging
import threading
from collections import deque, Counter
from datetime import datetime

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit

logger = logging.getLogger(__name__)

# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "nids-dashboard-secret")

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Shared in-memory state ────────────────────────────────────────────────────

MAX_LOG_ENTRIES = 500          # rolling window
_log_store: deque = deque(maxlen=MAX_LOG_ENTRIES)
_stats: dict = {
    "total_packets":  0,
    "total_attacks":  0,
    "blocked_ips":    0,
    "attack_counts":  Counter(),
    "severity_counts": Counter(),
    "start_time":     time.time(),
}
_blocked_ips: list = []

# Queue that main.py pushes DetectionResult dicts into
dashboard_queue: queue.Queue = queue.Queue(maxsize=1000)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/logs")
def api_logs():
    """Return the latest log entries as JSON (REST fallback)."""
    return jsonify(list(_log_store))


@app.route("/api/stats")
def api_stats():
    uptime = int(time.time() - _stats["start_time"])
    return jsonify({
        "total_packets":  _stats["total_packets"],
        "total_attacks":  _stats["total_attacks"],
        "blocked_ips":    _stats["blocked_ips"],
        "attack_counts":  dict(_stats["attack_counts"]),
        "severity_counts": dict(_stats["severity_counts"]),
        "uptime_seconds": uptime,
    })


@app.route("/api/blocked")
def api_blocked():
    return jsonify(_blocked_ips)


# ── Socket.IO events ──────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    """Send recent history to a newly connected client."""
    logger.debug("Browser connected to dashboard.")
    emit("history", list(_log_store))
    emit("stats", _build_stats_payload())


@socketio.on("disconnect")
def on_disconnect():
    logger.debug("Browser disconnected from dashboard.")


# ── Background worker ─────────────────────────────────────────────────────────

def _dashboard_worker():
    """
    Drain dashboard_queue and broadcast each event to all WebSocket clients.
    Runs as a daemon thread started by run_dashboard().
    """
    while True:
        try:
            record: dict = dashboard_queue.get(timeout=1)
        except queue.Empty:
            continue

        # Update in-memory state
        _log_store.appendleft(record)
        _stats["total_packets"] += 1

        if record.get("attack_type") != "Normal":
            _stats["total_attacks"] += 1

        _stats["attack_counts"][record.get("attack_type", "Unknown")] += 1
        _stats["severity_counts"][record.get("severity", "INFO")] += 1

        if record.get("blocked"):
            ip = record.get("src_ip")
            if ip and ip not in _blocked_ips:
                _blocked_ips.append(ip)
                _stats["blocked_ips"] += 1

        # Broadcast to all connected browsers
        socketio.emit("new_event", record)
        socketio.emit("stats", _build_stats_payload())


def _build_stats_payload() -> dict:
    uptime = int(time.time() - _stats["start_time"])
    return {
        "total_packets":   _stats["total_packets"],
        "total_attacks":   _stats["total_attacks"],
        "blocked_ips":     _stats["blocked_ips"],
        "attack_counts":   dict(_stats["attack_counts"]),
        "severity_counts": dict(_stats["severity_counts"]),
        "uptime_seconds":  uptime,
    }


def push_result(detection_dict: dict):
    """
    Called from main.py to enqueue a detection result for the dashboard.
    Safe to call from any thread.
    """
    try:
        # Ensure timestamp is human-readable
        if "timestamp" in detection_dict and isinstance(detection_dict["timestamp"], float):
            detection_dict["time_str"] = datetime.fromtimestamp(
                detection_dict["timestamp"]
            ).strftime("%H:%M:%S")
        dashboard_queue.put_nowait(detection_dict)
    except queue.Full:
        logger.warning("Dashboard queue full – dropping display event.")


def run_dashboard(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    """Start the background worker thread then the Flask-SocketIO server."""
    worker = threading.Thread(target=_dashboard_worker, daemon=True)
    worker.start()
    logger.info(f"Dashboard available at http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)
