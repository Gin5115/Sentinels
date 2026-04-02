# SENTINELS — Network Traffic Analyzer & IDS

> Real-time packet capture, heuristic threat detection, geo-IP visualization, and live device tracking — running locally in your browser.

---

## Overview

Sentinels is a self-hosted **Network Intrusion Detection System (NIDS)** built for security professionals and students. It captures every packet on your network interface in real time, runs them through a heuristic threat engine, and presents everything through a modern dark-themed web dashboard — no cloud, no subscriptions, no agents.

The entire stack runs locally. Start it with `sudo python run.py`, open `http://localhost:5000`, and you have full visibility into your network within seconds.

---

## Features

### Real-Time Monitoring
- Live packet capture via **Scapy** at the kernel level
- Virtual-scrolling live feed handles 50,000+ packets without lag
- Protocol distribution (TCP / UDP / ICMP / Other) updated in real time
- Top-talker chart showing highest-traffic IPs
- Packet rate badge (packets/sec)

### Threat Detection Engine
Five independent heuristic rules running on every packet:

| Rule | Trigger | Severity |
|------|---------|----------|
| SYN Flood | > 100 SYN-only packets / 5s from one IP | High |
| UDP Flood | > 500 UDP packets / 5s from public IP | Medium |
| ICMP Flood | > 300 ICMP packets / 5s from public IP | Medium |
| Port Scan | > 10 unique destination ports / 5s from one IP | Low |
| Blacklisted Port Access | Any connection to Telnet / RDP / SMB / Redis / MongoDB / MySQL / PostgreSQL | Info |

All threats are persisted to SQLite with full packet metadata and exportable to CSV.

### Geo-IP World Map
- **D3.js** Natural Earth projection rendered fully locally (no CDN)
- Animated circles on the map per resolved public IP
- Circle **size** = traffic volume (sqrt scale)
- Circle **colour** = green (clean) / red (flagged threat IP)
- Click any circle → popup with IP, city, coordinates, packet count, status
- Click any country row → popup listing every IP from that country
- Country breakdown table sorted by traffic volume
- IPs resolved incrementally via `ip-api.com` (8 per 5s cycle, rate-limit safe)

### Local Device Discovery
- Tracks every private IP (RFC 1918) seen in traffic
- Resolves MAC address → manufacturer via offline OUI database
- Reverse-DNS hostname lookup
- Per-device packet count, bytes transferred, last-seen timestamp
- Auto-refreshes every 5 seconds without page reload

### Live Packet Feed
- Filter by protocol (TCP / UDP / ICMP / Other)
- Filter by IP address (source or destination)
- Click any row for full packet details modal (payload, flags, ports, timestamps)
- Pause / resume capture without stopping the sniffer

### Settings & Controls
- **Network interface selector** — switch capture interface without restart
- **Session restart** — clear all in-memory stats and start fresh
- **CSV export** — download all threat records with timestamps and metadata
- **Database wipe** — one-click clear of threat history

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser                                  │
│  Dashboard │ Live Feed │ Geo Map │ Devices │ Logs │ Settings    │
│                    ↕ HTTP + SocketIO (long-polling)              │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                      Flask Application                           │
│                                                                  │
│  Routes (views.py)          SocketIO Event Handlers             │
│  ├─ GET /                   ├─ connect / disconnect             │
│  ├─ GET /feed               ├─ toggle_monitoring                │
│  ├─ GET /nodes              ├─ get_all_connections              │
│  ├─ GET /geo                ├─ resolve_geo / resolve_ip         │
│  ├─ GET /logs               ├─ get_interfaces                   │
│  ├─ GET /settings           ├─ start_capture / stop_capture     │
│  └─ REST /api/*             └─ restart_session                  │
│                                                                  │
│  Background Threads                                              │
│  ├─ PacketSniffer (Scapy)   → emit_packet() → SocketIO broadcast│
│  ├─ SystemMonitor           → system_usage event every 2s       │
│  └─ TopTalkersMonitor       → update_top_talkers every 2s       │
│                                                                  │
│  Per-Packet Pipeline                                             │
│  Scapy → parse headers → ThreatEngine.analyze()                 │
│              ↓                    ↓                             │
│        log to SQLite      update TrafficStats + NodeStats        │
│                                   ↓                             │
│                     socketio.emit('new_packet')                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                        Data Layer                                │
│  SQLite (instance/threats.db)     In-Memory (Python)            │
│  └─ threats table                 ├─ PACKET_BUFFER (deque 50K)  │
│     auto-created on startup       ├─ TrafficStats (Counter)     │
│                                   ├─ NODE_STATS (dict)          │
│                                   └─ THREAT_IPS (set)           │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

**Why SocketIO over WebSockets?**
Flask's threading mode uses long-polling which works reliably alongside Scapy's background thread. Pure WebSocket upgrades cause session drops in the development server with `async_mode='threading'`, so `allow_upgrades=False` is set.

**Why in-memory for packets?**
SQLite writes on every packet would bottleneck at high traffic rates. The circular deque (`maxlen=50000`) gives O(1) append/evict with zero disk I/O.

**Why Scapy over raw sockets?**
Scapy handles Ethernet frame parsing, protocol dissection, and TCP flag extraction across IPv4/IPv6 in one call. Raw sockets would require reimplementing all of that, plus it handles both Linux and Windows capture transparently.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Packet Capture | [Scapy](https://scapy.net/) 2.7+ |
| Web Framework | [Flask](https://flask.palletsprojects.com/) 3.x + Flask-SocketIO 5.x |
| Real-Time Transport | SocketIO long-polling (`async_mode='threading'`) |
| Database | SQLite 3 (built-in Python) |
| Device Fingerprinting | [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/) |
| System Metrics | [psutil](https://psutil.readthedocs.io/) |
| Geo-IP | [ip-api.com](http://ip-api.com/) (free, no API key required) |
| Frontend | HTML5 + Vanilla JS + [Tailwind CSS](https://tailwindcss.com/) (CDN) |
| Charts | [Chart.js](https://www.chartjs.org/) (CDN) |
| World Map | [D3.js](https://d3js.org/) v7 + [TopoJSON](https://github.com/topojson/topojson) (served locally) |
| World Atlas Data | [world-atlas](https://www.npmjs.com/package/world-atlas) 110m resolution (served locally) |

---

## Branches

| Branch | Description |
|--------|-------------|
| `main` | Original Windows implementation — the starting point of the project |
| `linux-implementation` | Full feature set — Linux/macOS compatible with all features added |

**`linux-implementation` is the recommended branch.** The `main` branch is behind and is missing several features:

| Feature | `main` (Windows) | `linux-implementation` |
|---------|:-----------------:|:----------------------:|
| Linux / macOS support | No | Yes |
| ICMP Flood detection rule | No | Yes |
| D3.js Geo-IP world map | No | Yes |
| Nodes / Logs auto-refresh | No | Yes |
| Interface selector in Settings | No | Yes |
| `requests` dependency declared | No | Yes |

### Switching branches

```bash
# Clone and switch to the full-featured branch
git clone https://github.com/Gin5115/Sentinels
cd Sentinels
git checkout linux-implementation
```

> Windows users can stay on `main` and follow the original Windows setup, but the geo map, ICMP flood rule, and several UI features will not be present.

---

## Installation

### Prerequisites

| Platform | Requirement |
|----------|------------|
| Linux | `libpcap` (usually pre-installed), Python 3.8+, `sudo` |
| macOS | `libpcap` (pre-installed), Python 3.8+, `sudo` |
| Windows | [Npcap](https://npcap.com/) installed, Python 3.8+, Administrator shell |

### Setup

```bash
# 1. Clone
git clone https://github.com/Gin5115/Sentinels
cd Sentinels

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run (root/admin required for raw packet access)
sudo venv/bin/python run.py       # Linux / macOS
python run.py                     # Windows (Administrator PowerShell)
```

Open **http://localhost:5000** in your browser.

> The app auto-creates `instance/threats.db` on first run. No database setup needed.

---

## Usage Guide

### Starting a Capture Session

1. Open the dashboard at `http://localhost:5000`
2. The **STATUS** indicator in the sidebar shows `Monitoring` when active
3. Click **⏸** to pause without stopping the sniffer thread
4. Click **↺** to clear all session data and restart fresh

### Switching Network Interface

1. Go to **Settings → Network Interface**
2. Select from the dropdown (e.g. `wlo1`, `eth0`, `enp0s3`)
3. Click **Apply** — the sniffer restarts on the new interface immediately

### Reading the Threat Logs

- Every detected threat is logged with timestamp, source/destination IP, protocol, type, and severity
- Click 👁 on any row to see the raw packet payload
- Click 🔍 to deep-dive the source IP (packet history, geo, hostname)
- Export all logs as **CSV** from Settings → Data Export

### Geo Map

- **Green dots** = clean IPs
- **Red dots** = IPs that triggered at least one threat alert
- **Dot size** scales with packet volume relative to the busiest tracked IP
- Public IPs resolve to lat/lon via ip-api.com — 8 per 5-second cycle
- Click any dot or country row for a detailed breakdown popup

---

## API Reference

All endpoints return JSON unless noted.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/packets` | Packet buffer. Params: `limit` (max 50000), `offset`, `ip` |
| `GET` | `/api/packet/<id>` | Full packet details including payload |
| `GET` | `/api/threats` | Threat log. Params: `limit` |
| `GET` | `/api/threats/export` | Download all threats as CSV file |
| `POST` | `/api/threats/delete/<id>` | Delete a single threat record |
| `POST` | `/api/threats/clear` | Wipe entire threat history |
| `GET` | `/api/nodes` | Active LAN devices as JSON |
| `GET` | `/api/geo/<ip>` | Resolve geo-location for any IP |
| `GET` | `/api/threat/<id>` | Full threat record including payload |

### SocketIO Events

**Client → Server**

| Event | Payload | Description |
|-------|---------|-------------|
| `toggle_monitoring` | `{target_state: bool}` | Start or stop the sniffer |
| `start_capture` | `{interface: string}` | Start on a specific interface |
| `stop_capture` | — | Stop the sniffer |
| `get_interfaces` | — | Request available network interfaces |
| `get_all_connections` | — | Request full connection list with geo data |
| `resolve_ip` | `{ip: string}` | Resolve IP to hostname/org |
| `resolve_geo` | `{ip: string}` | Resolve IP to country/city/lat/lon |
| `restart_session` | — | Clear all session data |

**Server → Client**

| Event | Payload | Description |
|-------|---------|-------------|
| `new_packet` | Lightweight packet metadata | Every captured packet |
| `threat_alert` | Threat object | Threat detected |
| `init_stats` | Counter snapshot | Sent on connect to sync state |
| `monitoring_status` | `{active, sniffer_running}` | Broadcast on state change |
| `system_usage` | CPU / RAM / disk stats | Every 2 seconds |
| `update_top_talkers` | Top 5 IP list | Every 2 seconds |
| `interfaces_list` | List of interface dicts | Response to `get_interfaces` |
| `ip_resolved` | `{ip, name}` | Async hostname result |
| `geo_resolved` | `{ip, country, city, flag, lat, lon}` | Async geo result |
| `all_connections_data` | Full connection list | Response to `get_all_connections` |
| `session_restarted` | Reset stats object | Broadcast after session clear |

---

## Project Structure

```
Sentinels/
├── run.py                           # Entry point
├── config.py                        # Flask configuration
├── requirements.txt                 # Python dependencies
│
├── app/
│   ├── __init__.py                  # App factory, SocketIO init
│   │
│   ├── sniffer/
│   │   └── capture.py               # PacketSniffer (Scapy), cross-platform interface detection
│   │
│   ├── utils/
│   │   ├── threat_engine.py         # 5-rule heuristic detection engine
│   │   ├── stats_manager.py         # In-memory per-IP traffic counters
│   │   └── ip_resolver.py           # Hostname + geo-IP resolution with caching
│   │
│   ├── models/
│   │   ├── threat.py                # SQLite threat persistence
│   │   └── nodes.py                 # LAN device tracking + MAC vendor lookup
│   │
│   ├── routes/
│   │   └── views.py                 # HTTP routes + REST API endpoints
│   │
│   ├── events/
│   │   └── socket_events.py         # All SocketIO event handlers + background threads
│   │
│   ├── templates/
│   │   ├── base.html                # Sidebar, nav, system resource monitor
│   │   ├── index.html               # Dashboard (stats cards, charts, top talkers)
│   │   ├── feed.html                # Live packet feed with filtering
│   │   ├── nodes.html               # Local LAN devices
│   │   ├── geo.html                 # D3 geo-IP world map
│   │   ├── logs.html                # Threat history table
│   │   └── settings.html            # Interface selector, export, database management
│   │
│   └── static/
│       ├── css/style.css
│       ├── js/
│       │   ├── main.js              # Dashboard logic
│       │   ├── feed.js              # Live feed + virtual scroll + filters
│       │   ├── geo.js               # D3 world map, popups, geo resolution
│       │   ├── nodes.js             # 5s auto-refresh for device cards
│       │   ├── logs.js              # Threat table + 5s auto-refresh
│       │   ├── settings.js          # Interface selector + export handlers
│       │   ├── ip-details.js        # IP deep-dive side panel
│       │   ├── d3.min.js            # D3.js v7 (local, no CDN)
│       │   └── topojson-client.min.js
│       └── data/
│           └── countries-110m.json  # World atlas TopoJSON (local, no CDN)
│
└── instance/
    └── threats.db                   # SQLite (auto-created on first run)
```

---

## Threat Detection Details

### How the Engine Works

Every captured packet passes through two stages:

**Stage 1 — Rule-based** (`capture.py`): immediate single-packet check.
Example: bare SYN flag + packet size < 60 bytes → possible SYN scan.

**Stage 2 — Heuristic engine** (`threat_engine.py`): stateful 5-second sliding window per source IP. Counters reset every 5 seconds. A cooldown (`_recent_alerts`, 5s) prevents duplicate alerts for the same IP.

Private IPs (RFC 1918, loopback, link-local, IPv6 ULA) are exempt from all flood detection rules.

### Tuning Thresholds

Edit `app/utils/threat_engine.py`:

```python
SYN_FLOOD_THRESHOLD  = 100   # lower = more sensitive
UDP_FLOOD_THRESHOLD  = 500   # raise if seeing false positives on media streams
ICMP_FLOOD_THRESHOLD = 300   # raise if network monitoring generates lots of pings
PORT_SCAN_THRESHOLD  = 10    # lower = detect slower/stealthier scans
```

### Adding a Custom Rule

Add a new block inside `ThreatEngine.analyze_packet()`:

```python
# === Rule N: Your Custom Rule ===
if <condition>:
    with self._lock:
        self._my_track[src_ip] += 1
        count = self._my_track[src_ip]
    if count > self.MY_THRESHOLD:
        threat_key = f"my_rule:{src_ip}"
        if self._should_alert(threat_key):
            return {
                'type':        'My Threat Type',
                'ip':          src_ip,
                'severity':    self.SEVERITY_HIGH,
                'description': f'Description with {count} as context',
            }
```

Remember to also add tracking in `__init__`, `_reset_window`, `get_stats`, and `clear`.

---

## Limitations

- **Development server only** — not production-grade. For deployment use Gunicorn + gevent.
- **WebSocket upgrades disabled** — `allow_upgrades=False` because Scapy threading conflicts with WebSocket upgrades. Long-polling is reliable and sufficient.
- **Geo-IP requires internet** — public IPs show as "Unknown" on air-gapped networks.
- **IPv6 partial support** — packets are captured and classified but geo and node tracking are IPv4-focused.
- **Single interface** — the sniffer binds to one interface at a time.

---

## Linux Quick Reference

```bash
# Start
sudo venv/bin/python run.py

# List interfaces
ip link show

# Install libpcap if missing
sudo apt install libpcap-dev        # Debian/Ubuntu
sudo dnf install libpcap-devel      # Fedora/RHEL

# Grant raw socket capability instead of running as root
sudo setcap cap_net_raw+ep venv/bin/python
venv/bin/python run.py
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
