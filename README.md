# AI-Enhanced Network Intrusion Detection System (AI-NIDS)
  
> Real-time ML-powered network intrusion detection with live web dashboard.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         main.py (Orchestrator)                  │
└────────────┬──────────────────────────────────────┬────────────┘
             │                                      │
    ┌────────▼────────┐                   ┌─────────▼──────────┐
    │  PacketCapture  │                   │  Flask Dashboard   │
    │  (Scapy/Sim)    │                   │  + Socket.IO       │
    └────────┬────────┘                   └────────────────────┘
             │ PacketFeatures                        ▲
    ┌────────▼────────┐                              │
    │IntrusionDetector│──── DetectionResult ─────────┤
    │  (RandomForest) │                              │
    └────────┬────────┘                    ┌─────────┴──────────┐
             │                             │   AlertSystem      │
    ┌────────▼────────┐                   │ (Console + Email)  │
    │FirewallManager  │                   └────────────────────┘
    │(Windows netsh)  │
    └─────────────────┘
```

---

## Project Structure

```
AI-NIDS/
├── dataset/
│   └── nsl_kdd.csv              ← Download from Kaggle (see below)
├── model/
│   ├── preprocess_data.py       ← Data cleaning & encoding
│   ├── train_model.py           ← Model training & evaluation
│   ├── intrusion_model.pkl      ← Generated after training
│   ├── scaler.pkl               ← Generated after training
│   └── encoders.pkl             ← Generated after training
├── network/
│   └── packet_capture.py        ← Scapy live capture + sim mode
├── detection/
│   └── intrusion_detection.py   ← ML inference engine
├── alerts/
│   ├── alert_system.py          ← Console + file + email routing
│   └── email_alert.py           ← SMTP email sender
├── security/
│   └── firewall.py              ← Windows netsh IP blocking
├── dashboard/
│   ├── app.py                   ← Flask + Socket.IO server
│   ├── templates/index.html     ← Real-time web UI
│   └── static/style.css         ← Cyberpunk terminal theme
├── logs/                        ← Auto-created at runtime
│   ├── nids.log
│   ├── alerts.jsonl
│   └── blocked_ips.json
├── main.py                      ← Entry point
└── requirements.txt
```

---

## Step-by-Step Setup

### 1. Clone / create the project folder

```bash
cd ~
# (your AI-NIDS folder is already set up)
cd AI-NIDS
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> **Windows Note:** Scapy requires **Npcap**. Please install [Npcap](https://npcap.com/) in "WinPcap API-compatible Mode" to enable live packet capture.

### 4. Download the NSL-KDD Dataset

Download `KDDTrain+.txt` from one of:
- **Kaggle**: https://www.kaggle.com/datasets/hassan06/nslkdd
- **UNB direct**: https://www.unb.ca/cic/datasets/nsl.html

Rename it and place at:
```
AI-NIDS/dataset/nsl_kdd.csv
```

> The file has no header row — the preprocessing script handles this automatically.

### 5. Train the model

```bash
cd model/
python train_model.py
cd ..
```

Expected output:
```
Test Accuracy: 99.xx%
Classification Report:
              precision    recall  f1-score
Normal            0.99      0.99      0.99
DoS               0.99      0.99      0.99
...
Model saved to model/intrusion_model.pkl
```

---

## Running the System

### Option A – Simulation Mode (no root required)

Perfect for demos and development:

```bash
python main.py --simulate
```

### Option B – Live Packet Capture (requires Administrator)

Open PowerShell as Administrator:

```bash
python main.py
```

With specific interface:
```bash
python main.py --interface Ethernet
```

### Option C – Custom port / no firewall

```bash
python main.py --simulate --port 8080 --no-firewall
```

---

## Accessing the Dashboard

Open your browser at:  
**http://localhost:5000**

The dashboard shows:
- 📊 **Live stats** – packets, attacks, blocked IPs, uptime
- 📈 **Charts** – attack distribution, severity breakdown, traffic timeline
- 📋 **Event log** – real-time table with severity badges and confidence bars
- 🔒 **Blocked IPs** – automatically blocked malicious sources

---

## Email Alerts (Optional)

Set environment variables before running:

```bash
export NIDS_SMTP_HOST=smtp.gmail.com
export NIDS_SMTP_PORT=587
export NIDS_SMTP_USER=your@gmail.com
export NIDS_SMTP_PASS=your-app-password   # Gmail app password
export NIDS_ALERT_TO=admin@example.com

python main.py --simulate
```

Then enable in code: set `"enable_email": True` in `main.py` DEFAULT_CONFIG.

---

## Attack Classification

| Class        | Examples in NSL-KDD                    | Severity |
|--------------|----------------------------------------|----------|
| Normal       | Regular traffic                        | INFO     |
| DoS          | neptune, smurf, pod, teardrop          | HIGH     |
| PortScan     | ipsweep, nmap, portsweep, satan        | MEDIUM   |
| BruteForce   | guess_passwd, ftp_write, imap          | HIGH     |
| Exploit      | buffer_overflow, rootkit, sqlattack    | CRITICAL |

---

## Module Interactions

```
main.py
  │
  ├─ PacketCapture.start()
  │    └─ Scapy sniff() or simulation loop
  │         └─ extract_features(packet) → PacketFeatures
  │              └─ packet_queue.put(features)
  │
  ├─ DetectionPipeline.run()  [thread]
  │    └─ packet_queue.get() → PacketFeatures
  │         ├─ IntrusionDetector.detect() → DetectionResult
  │         ├─ AlertSystem.process(result)  → console + JSONL + email
  │         ├─ FirewallManager.maybe_block(result) → iptables
  │         └─ dashboard_app.push_result(result.to_dict())
  │
  └─ dashboard_app.run_dashboard()  [main thread, blocking]
       ├─ _dashboard_worker()  [thread] → drains dashboard_queue
       │    └─ socketio.emit('new_event', record)
       └─ Flask routes: /, /api/logs, /api/stats, /api/blocked
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `Model not found` | Run `python model/train_model.py` first |
| `Permission denied` on sniff | Run as Administrator or use `--simulate` |
| Firewall errors | Requires Administrator; use `--no-firewall` otherwise |
| Dashboard not loading | Check port 5000 is free; use `--port 8080` |
| Email not sending | Check env vars; use Gmail App Password (not account password) |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |

---

## Technologies Used

| Component        | Technology              |
|------------------|-------------------------|
| ML Model         | scikit-learn RandomForest |
| Dataset          | NSL-KDD (41 features)   |
| Packet Capture   | Scapy                   |
| Web Framework    | Flask + Flask-SocketIO  |
| Real-time Comms  | WebSockets (Socket.IO)  |
| Firewall         | Windows Firewall (netsh)|
| Serialisation    | joblib / JSON Lines     |
| Visualisation    | Chart.js                |

---

## Academic Notes

- The NSL-KDD dataset is the standard benchmark for NIDS research
- RandomForest provides ~99% accuracy on NSL-KDD; a good baseline to discuss
- Feature engineering from raw packets is a known limitation — connection-level features (duration, byte counts both ways) require stateful tracking
- Production NIDS (Snort, Suricata) use rule-based + ML hybrid approaches
- Discuss false positive rate as a key metric in your report
