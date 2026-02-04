# Sentinels Network Monitor

Sentinels is a real-time network traffic analysis and threat detection tool. It provides a modern dashboard for monitoring network packets, visualizing traffic statistics, and detecting potential security threats such as port scans and flood attacks.

## Features

- **Real-time Packet Monitoring**: View live network traffic with detailed packet metadata.
- **Threat Detection**: Heuristic analysis engine to detect:
  - SYN Floods
  - UDP Floods
  - Port Scans
  - Blacklisted Port Access
- **Geo-Location Integration**: Automatically resolves IP addresses to physical locations (City, Country) with flag indicators.
- **Interactive Dashboard**:
  - Traffic volume charts
  - Protocol distribution statistics
  - Top talkers (active IPs)
  - Active connections list
- **Deep Dive Inspection**: Detailed analysis of specific IP addresses including traffic breakdown and packet history.
- **Threat Logs**: Persistent history of detected threats with search and inspect capabilities.
- **Modern UI**: Dark-themed, responsive interface built for professionals.

## Technology Stack

- **Backend**: Python, Flask, Flask-SocketIO
- **Network Engine**: Scapy
- **Database**: SQLite (for threat persistence)
- **Frontend**: HTML5, Tailwind CSS, Vanilla JavaScript
- **Visualization**: Chart.js

## Installation

### Prerequisites
- Python 3.8 or higher
- Npcap (Windows) or libpcap (Linux/macOS) for packet capture

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Sentinels
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the Database**
   The application automatically initializes the SQLite database on first run.

## Usage

1. **Start the Application**
   Run the application with administrative privileges (required for packet sniffing):
   ```bash
   # Windows (PowerShell as Admin)
   python run.py
   
   # Linux/macOS (sudo required)
   sudo python run.py
   ```

2. **Access the Dashboard**
   Open your web browser and navigate to:
   `http://localhost:5000`

3. **Select Interface**
   On startup, the application will attempt to bind to the default active network interface. You can configure specific interfaces in the settings.

## Configuration

Settings can be adjusted in `config.py` or via environment variables:

- `SECRET_KEY`: Flask secret key
- `DEBUG`: Enable/disable debug mode

### Threat Detection Thresholds
Adjust thresholds in `app/utils/threat_engine.py` to tune sensitivity:
- `SYN_FLOOD_THRESHOLD`
- `UDP_FLOOD_THRESHOLD`
- `PORT_SCAN_THRESHOLD`

## Project Structure

```
Sentinels/
├── app/
│   ├── events/         # SocketIO event handlers
│   ├── models/         # Database models (SQLite)
│   ├── routes/         # Flask route definitions
│   ├── sniffer/        # Scapy packet capture logic
│   ├── static/         # CSS, JS, and images
│   ├── templates/      # HTML templates
│   └── utils/          # Helpers (IP resolution, Threat Engine)
├── instance/           # SQLite database location
├── config.py           # App configuration
├── run.py              # Entry point
└── requirements.txt    # Python dependencies
```

## API Documentation

The application exposes several API endpoints for data access:

- `GET /api/packets`: Retrieve packet buffer (supports limit/offset)
- `GET /api/threats`: Retrieve recorded threat logs
- `GET /api/geo/<ip>`: Resolve geo-location for a specific IP
- `GET /api/packet/<id>`: Get full details for a specific packet
