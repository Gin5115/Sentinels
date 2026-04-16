# Sentinels

Self-hosted network intrusion detection system with dual-layer heuristic + ML threat detection and a real-time web dashboard.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey)
![scikit--learn](https://img.shields.io/badge/scikit--learn-RandomForest-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

Sentinels is a self-hosted **Network Intrusion Detection System (NIDS)** that captures every packet on your network interface in real time and runs them through two independent detection layers: a stateful heuristic engine and a Random Forest ML model trained on CICIDS-2017 attack patterns. Everything is presented through a modern dark-themed web dashboard — no cloud, no subscriptions, no agents.

Start it with `sudo python run.py`, open `http://localhost:5000`, and you have full network visibility within seconds.

### Key Features

- **Dual-Layer Detection**: heuristic sliding-window rules + Random Forest ML model run in parallel, or toggle either on/off from the Settings page at runtime.
- **Machine Learning Engine**: Random Forest (200 trees) trained on CICIDS-2017 features — detects DoS, PortScan, BruteForce, Botnet, WebAttack, Infiltration, Heartbleed with per-class confidence scores.
- **Local Model Retraining**: `retrain_local.py` generates synthetic flows matched to your FlowTracker's feature scales and retrains the model without any external dataset.
- **Heuristic Threat Engine**: five stateful rules in a 5-second sliding window — SYN Flood, UDP Flood, ICMP Flood, Port Scan, Blacklisted Port — all thresholds adjustable live from the Settings UI without a server restart.
- **Real-Time Dashboard**: live packet rate, protocol distribution donut, traffic volume chart, top talkers — all pushed via SocketIO.
- **Geo-IP World Map**: D3.js Natural Earth projection fully served locally, animated circles per resolved public IP, country breakdown table.
- **Local Device Discovery**: passive LAN tracking — no ARP scans, no active probes. Resolves MAC → vendor and reverse-DNS hostname in background threads.
- **Live Packet Feed**: virtual-scroll feed handles 50 000+ packets; filterable by protocol or IP; click any row for full payload modal.
- **Attack Simulation**: `simulate.py` replays CICIDS-2017-style traffic against the local stack to validate both detection layers end-to-end.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                          Browser                                │
│  Dashboard │ Live Feed │ Geo Map │ Devices │ Logs │ Settings   │
│                   ↕ HTTP + SocketIO (long-polling)              │
└───────────────────────────┬────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────┐
│                     Flask Application                           │
│                                                                 │
│  Routes (views.py)           SocketIO Event Handlers           │
│  ├─ REST /api/*              ├─ toggle_monitoring              │
│  ├─ /api/ml/status           ├─ start_capture / stop_capture   │
│  ├─ /api/ml/reload           ├─ get_all_connections            │
│  ├─ /api/settings/detection  ├─ resolve_geo / resolve_ip       │
│  └─ /api/settings/heuristic  └─ restart_session                │
│                                                                 │
│  Per-Packet Pipeline                                            │
│  Scapy ──► parse headers ──► ThreatEngine.analyze()            │
│                 │                     │                         │
│           log to SQLite        FlowTracker.update()             │
│                                       │                         │
│                    (on flow complete) │                         │
│                              MLEngine.classify_flow()           │
│                                       │                         │
│                      socketio.emit('new_packet' / 'threat_alert')
└───────────────────────────┬────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────┐
│                        Data Layer                               │
│  SQLite (instance/threats.db)    In-Memory (Python)            │
│  └─ threats table                ├─ PACKET_BUFFER (deque 50K)  │
│     auto-created on startup      ├─ PACKET_DETAIL_BUFFER (1K)  │
│                                  ├─ FlowTracker (dict)         │
│                                  ├─ TrafficStats (Counter)     │
│                                  ├─ NODE_STATS (dict)          │
│                                  └─ THREAT_IPS (set)           │
└────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

| Platform | Requirement |
|----------|------------|
| Linux | `libpcap`, Python 3.8+, `sudo` |
| macOS | `libpcap` (pre-installed), Python 3.8+, `sudo` |
| Windows | [Npcap](https://npcap.com/), Python 3.8+, Administrator shell |

### 1. Clone the repo

```bash
git clone https://github.com/Gin5115/Sentinels.git
cd Sentinels
git checkout linux-implementation
```

### 2. Create virtual environment and install dependencies

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. (Optional) Train the ML model

A pre-trained model is included. To retrain on your own traffic patterns:

```bash
python retrain_local.py
# Trains Random Forest on synthetic CICIDS-2017-style flows
# Saves model to app/ml/sentinels_rf_model.pkl
```

### 4. Run

```bash
sudo venv/bin/python run.py       # Linux / macOS
python run.py                     # Windows (Administrator PowerShell)
```

Open **http://localhost:5000**.

> SQLite database at `instance/threats.db` is auto-created on first run.

### 5. (Optional) Simulate attacks for testing

```bash
python simulate.py
# Replays CICIDS-2017-style attack traffic against the local detection stack
```

## Configuration

### Detection Mode (Settings UI or API)

| Mode | Behaviour |
|------|-----------|
| `heuristic` | Rule-based engine only |
| `ml` | Random Forest only |
| `both` | Both layers run in parallel (default) |

Switch live via **Settings → Detection Mode** or `POST /api/settings/detection`.

### Heuristic Thresholds (Settings UI or API)

All thresholds are runtime-adjustable from **Settings → Heuristic Thresholds** without a server restart.

| Threshold | Default | Description |
|-----------|---------|-------------|
| `syn_flood_threshold` | 100 | SYN-only packets / 5 s from one IP |
| `udp_flood_threshold` | 500 | UDP packets / 5 s from public IP |
| `icmp_flood_threshold` | 300 | ICMP packets / 5 s from public IP |
| `port_scan_threshold` | 10 | Unique destination ports / 5 s from one IP |
| `window_duration` | 5.0 | Sliding window size (seconds) |
| `alert_cooldown` | 5.0 | Minimum seconds between duplicate alerts |

### False Positive Mitigations

| Rule | Mitigation |
|------|-----------|
| DNS servers (8.8.8.8, 1.1.1.1 etc.) flagged as port scanners | Added to trusted IP set; `src_port==53` responses skipped |
| LAN service discovery (mDNS, SSDP) classified by ML | LAN↔LAN flows are skipped from ML inference |
| Background app traffic (keepalives) triggering ML | Confidence threshold set to 60% minimum |
| 172.20.x.x and similar RFC 1918 ranges not excluded | Full 172.16.0.0/12 range covered |

## API Reference

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/packets` | Packet buffer. Params: `limit`, `offset`, `ip` |
| `GET` | `/api/packet/<id>` | Full packet details including payload |
| `GET` | `/api/threats` | Threat log. Params: `limit` |
| `GET` | `/api/threats/export` | Download all threats as CSV |
| `POST` | `/api/threats/clear` | Wipe entire threat history |
| `GET` | `/api/nodes` | Active LAN devices as JSON |
| `GET` | `/api/threat/<id>` | Full threat record including payload |
| `GET` | `/api/ml/status` | ML engine status (loaded, classes, model path) |
| `POST` | `/api/ml/reload` | Reload model from disk without restart |
| `GET` | `/api/settings/detection` | Get current detection mode |
| `POST` | `/api/settings/detection` | Set detection mode (`heuristic` / `ml` / `both`) |
| `GET` | `/api/settings/heuristic` | Get all heuristic thresholds |
| `POST` | `/api/settings/heuristic` | Update one or more thresholds |
| `GET` | `/api/debug/ml` | Classify last N flows and return raw scores |

### SocketIO Events

**Client → Server**

| Event | Payload | Description |
|-------|---------|-------------|
| `toggle_monitoring` | `{target_state: bool}` | Start or stop the sniffer |
| `start_capture` | `{interface: string}` | Start on a specific interface |
| `stop_capture` | — | Stop the sniffer |
| `get_interfaces` | — | Request available network interfaces |
| `get_all_connections` | — | Full connection list with geo data |
| `resolve_ip` | `{ip: string}` | Resolve IP to hostname/org |
| `resolve_geo` | `{ip: string}` | Resolve IP to country/city/lat/lon |
| `restart_session` | — | Clear all session data |

**Server → Client**

| Event | Payload | Description |
|-------|---------|-------------|
| `new_packet` | Lightweight packet metadata | Every captured packet |
| `threat_alert` | Threat object | Threat detected (heuristic or ML) |
| `init_stats` | Counter snapshot | Sent on connect to sync state |
| `monitoring_status` | `{active, sniffer_running}` | Broadcast on state change |
| `system_usage` | RAM / disk stats | Every 2 seconds |
| `update_top_talkers` | Top 5 IP list | Every 2 seconds |
| `session_restarted` | Reset stats object | Broadcast after session clear |

## ML Detection Details

### How Flows Are Built

`FlowTracker` groups raw packets into bidirectional flows using a canonical key `(min(src,dst), max(src,dst), src_port, dst_port, protocol)`. When a flow finishes (FIN/RST or 30 s idle timeout), it extracts 20 CICIDS-2017 features and passes them to `MLEngine.classify_flow()`.

### Features Used

Flow Duration, Total Fwd/Bwd Packets, Fwd/Bwd Packet Length Max/Min/Mean/Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean/Std, Fwd IAT Mean/Std, SYN/FIN/RST/PSH/ACK Flag Counts, Average Packet Size, Down/Up Ratio.

### Attack Classes & Confidence Targets

| Class | Severity | Typical Confidence |
|-------|----------|--------------------|
| DoS | HIGH | ~68% |
| PortScan | LOW | ~99% |
| BruteForce | HIGH | ~94% |
| Botnet | CRITICAL | ~90% |
| WebAttack | MEDIUM | ~78% |
| Infiltration | CRITICAL | varies |
| Heartbleed | CRITICAL | varies |

Minimum confidence threshold: **60%** — flows below this are silently dropped.

### Retraining

```bash
python retrain_local.py
```

Generates 4 200 synthetic flows (1 200 Normal + 600 × 5 attack classes) using the same feature extraction logic as `FlowTracker`, so feature scales match exactly. Trains RF(n_estimators=200, max_depth=20, class_weight='balanced') and saves `app/ml/sentinels_rf_model.pkl`.

## Project Structure

```
Sentinels/
├── run.py                           # Entry point
├── config.py                        # Flask configuration
├── requirements.txt                 # Python dependencies
├── retrain_local.py                 # Retrain RF model on synthetic flows
├── train_model.py                   # Original training script (CICIDS-2017 CSV)
├── simulate.py                      # Attack traffic simulation for testing
│
├── app/
│   ├── __init__.py                  # App factory, SocketIO init
│   │
│   ├── ml/
│   │   └── sentinels_rf_model.pkl   # Pre-trained Random Forest bundle
│   │
│   ├── sniffer/
│   │   └── capture.py               # PacketSniffer (Scapy), FlowTracker integration
│   │
│   ├── utils/
│   │   ├── threat_engine.py         # Heuristic detection, runtime-adjustable thresholds
│   │   ├── ml_engine.py             # MLEngine wrapper around scikit-learn pipeline
│   │   ├── flow_tracker.py          # Bidirectional flow assembly + feature extraction
│   │   ├── detection_config.py      # Detection mode toggle (heuristic / ml / both)
│   │   ├── stats_manager.py         # In-memory per-IP traffic counters
│   │   └── ip_resolver.py           # Hostname + geo-IP resolution with caching
│   │
│   ├── models/
│   │   ├── threat.py                # SQLite threat persistence
│   │   └── nodes.py                 # LAN device tracking + MAC vendor lookup
│   │
│   ├── routes/
│   │   └── views.py                 # HTTP routes, REST API, ML + settings endpoints
│   │
│   ├── events/
│   │   └── socket_events.py         # SocketIO handlers, PACKET_BUFFER, background threads
│   │
│   ├── templates/
│   │   ├── base.html                # Sidebar, nav, system resource monitor
│   │   ├── index.html               # Dashboard (stats cards, charts, top talkers)
│   │   ├── feed.html                # Live packet feed with filtering
│   │   ├── nodes.html               # Local LAN devices
│   │   ├── geo.html                 # D3 geo-IP world map + country breakdown
│   │   ├── logs.html                # Threat history table (heuristic + ML)
│   │   └── settings.html            # Interface, detection mode, heuristic thresholds
│   │
│   └── static/
│       ├── css/style.css
│       ├── js/
│       │   ├── main.js              # Dashboard logic
│       │   ├── feed.js              # Live feed + virtual scroll + filters
│       │   ├── geo.js               # D3 world map, popups, geo resolution
│       │   ├── nodes.js             # 5s auto-refresh for device cards
│       │   ├── logs.js              # Threat table + 5s auto-refresh
│       │   ├── settings.js          # Interface selector, detection mode, threshold UI
│       │   ├── ip-details.js        # IP deep-dive side panel
│       │   ├── d3.min.js            # D3.js v7 (local, no CDN)
│       │   └── topojson-client.min.js
│       └── data/
│           └── countries-110m.json  # World atlas TopoJSON (local, no CDN)
│
└── instance/
    └── threats.db                   # SQLite (auto-created on first run)
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Packet Capture | [Scapy](https://scapy.net/) 2.7+ |
| Web Framework | [Flask](https://flask.palletsprojects.com/) 3.x + Flask-SocketIO 5.x |
| Real-Time Transport | SocketIO long-polling (`async_mode='threading'`) |
| ML Model | [scikit-learn](https://scikit-learn.org/) RandomForestClassifier + LabelEncoder |
| ML Persistence | [joblib](https://joblib.readthedocs.io/) |
| Feature Engineering | [NumPy](https://numpy.org/) |
| Database | SQLite 3 (built-in Python) |
| Device Fingerprinting | [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/) |
| System Metrics | [psutil](https://psutil.readthedocs.io/) |
| Geo-IP | [ip-api.com](http://ip-api.com/) (free, no API key) |
| Frontend | HTML5 + Vanilla JS + [Tailwind CSS](https://tailwindcss.com/) (CDN) |
| Charts | [Chart.js](https://www.chartjs.org/) (CDN) |
| World Map | [D3.js](https://d3js.org/) v7 + TopoJSON (served locally) |

## Replicating on Another Machine

Full step-by-step for getting Sentinels running on a fresh machine from scratch.

### Step 1 — Install system dependencies

**Ubuntu / Debian**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git libpcap-dev
```

**Fedora / RHEL / Rocky**
```bash
sudo dnf install -y python3 python3-pip git libpcap-devel
```

**macOS**
```bash
# libpcap is pre-installed. Install Python via Homebrew if needed:
brew install python git
```

**Windows**
1. Install [Python 3.8+](https://www.python.org/downloads/) (check "Add to PATH")
2. Install [Git](https://git-scm.com/download/win)
3. Install [Npcap](https://npcap.com/) — required for raw packet capture

---

### Step 2 — Clone the repository

```bash
git clone https://github.com/Gin5115/Sentinels.git
cd Sentinels
git checkout linux-implementation
```

The pre-trained ML model (`app/ml/sentinels_rf_model.pkl`) is included in the repo — no separate download needed.

---

### Step 3 — Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
```

---

### Step 4 — Install Python dependencies

```bash
pip install -r requirements.txt
```

This installs Flask, Scapy, scikit-learn, numpy, joblib, psutil, and all other dependencies listed in `requirements.txt`.

---

### Step 5 — Run

```bash
# Linux / macOS — root required for raw packet access
sudo venv/bin/python run.py

# Windows — run from an Administrator PowerShell
python run.py
```

Open **http://localhost:5000** in a browser.

If you want the dashboard accessible from other devices on your network, it's already bound to `0.0.0.0:5000` — just open `http://<this-machine-ip>:5000` from any other device.

---

### Step 6 — (Optional) Retrain the ML model

The included model was trained on synthetic CICIDS-2017 flows. If you want to retrain it to match your own network's traffic patterns:

```bash
python retrain_local.py
```

This takes about 30 seconds and overwrites `app/ml/sentinels_rf_model.pkl`.

---

### Troubleshooting

| Problem | Fix |
|---------|-----|
| `Permission denied` on Linux | Run with `sudo venv/bin/python run.py` |
| `No module named 'scapy'` | Virtual environment not activated — run `source venv/bin/activate` first |
| `libpcap not found` | Install `libpcap-dev` (Debian) or `libpcap-devel` (Fedora) |
| Dashboard loads but no packets | Wrong interface selected — go to **Settings → Network Interface** and pick the correct one |
| Port 5000 blocked from other devices | Open it: `sudo ufw allow 5000/tcp` (Ubuntu) or `sudo firewall-cmd --add-port=5000/tcp --permanent && sudo firewall-cmd --reload` (Fedora) |
| `eventlet` error on Python 3.12+ | Run `pip install eventlet==0.36.1` to get the version with 3.12 fixes |

---

## Accessing from Another Machine

Sentinels binds to `0.0.0.0:5000` by default, so the dashboard is reachable from any device on your network — not just the machine running it.

### Setup

1. **Run on the monitoring machine** (the one doing packet capture) as normal:

   ```bash
   sudo venv/bin/python run.py
   ```

2. **Open from another device** on the same network:

   ```
   http://<monitoring-machine-ip>:5000
   ```

   Find the monitoring machine's IP with:

   ```bash
   ip addr show        # Linux
   ipconfig            # Windows
   ```

3. **Allow the port through the firewall** if the dashboard doesn't load:

   ```bash
   # Fedora / RHEL
   sudo firewall-cmd --add-port=5000/tcp --permanent
   sudo firewall-cmd --reload

   # Ubuntu / Debian
   sudo ufw allow 5000/tcp
   ```

> **Note**: packet capture still runs on the monitoring machine only — the remote browser is just viewing the dashboard. Whoever opens `http://<ip>:5000` sees the same live data.

## Branches

| Branch | Description |
|--------|-------------|
| `main` | Original Windows implementation |
| `linux-implementation` | Full feature set — Linux/macOS, ML engine, all UI features |

**`linux-implementation` is the recommended branch.**

## Disclaimer

This tool is for **educational and research purposes only**. Packet capture requires root/administrator privileges and should only be used on networks you own or have explicit permission to monitor. The authors are not responsible for any misuse.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
