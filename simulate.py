"""
Sentinels - Attack Simulation Script
=====================================
Simulates real network attacks to test both detection systems:
  - Heuristic rules (ThreatEngine) — triggers instantly per-packet
  - ML classifier (RandomForest)   — triggers when a flow completes

Run with sudo (raw packet crafting requires root):
    sudo venv/bin/python simulate.py

Select an attack from the menu, or run all:
    sudo venv/bin/python simulate.py --all
"""

import sys
import time
import random
import argparse

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Ether, Raw,
        send, sendp, get_if_list, conf,
        RandShort, RandMAC
    )
except ImportError:
    print('Scapy not found. Run: pip install scapy')
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────

# Spoofed attacker IPs (public, routable — won't be filtered as private)
ATTACKER_IPS = [
    '198.51.100.10',   # TEST-NET-3 (RFC 5737 — safe for simulation)
    '198.51.100.20',
    '198.51.100.30',
    '203.0.113.50',
    '203.0.113.99',
]

import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '192.168.1.1'

def get_local_iface_and_mac():
    """Return (interface_name, mac_address) for the active interface."""
    try:
        import subprocess
        result = subprocess.check_output(
            "ip route get 8.8.8.8 | grep -oP 'dev \\K\\S+'",
            shell=True
        ).decode().strip()
        iface = result
        with open(f'/sys/class/net/{iface}/address') as f:
            mac = f.read().strip()
        return iface, mac
    except Exception:
        return None, None

TARGET_IP  = get_local_ip()
IFACE, LOCAL_MAC = get_local_iface_and_mac()

def pkt(src_ip, dst_ip=None, **kwargs):
    """
    Build an Ethernet-wrapped IP packet aimed at the local machine's MAC.
    Using sendp() + explicit dst MAC eliminates the 'MAC not found' warnings.
    """
    dst_ip = dst_ip or TARGET_IP
    eth = Ether(src=RandMAC(), dst=LOCAL_MAC)
    ip  = IP(src=src_ip, dst=dst_ip)
    return eth / ip / kwargs.get('payload')

def tx(packets, iface=None):
    """Send a list of Ethernet packets on the local interface."""
    sendp(packets, iface=iface or IFACE, verbose=False)

# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(title):
    print(f'\n{"─" * 55}')
    print(f'  {title}')
    print(f'{"─" * 55}')

def done(n, label):
    print(f'  [+] Sent {n} packets  →  expect: {label}')

# ── Heuristic Attacks ─────────────────────────────────────────────────────────

def sim_syn_flood():
    """
    SYN Flood — Rule 1
    Sends 150 TCP SYN packets from one IP in ~1 second.
    Threshold: >100 SYN-only packets in 5 seconds from one IP → HIGH alert.
    """
    banner('SYN FLOOD  (Heuristic — Rule 1)')
    print(f'  Attacker : 198.51.100.10  →  Target : {TARGET_IP}:80')
    print('  Sending 150 SYN packets...')

    pkts = [
        Ether(src=RandMAC(), dst=LOCAL_MAC) /
        IP(src='198.51.100.10', dst=TARGET_IP) /
        TCP(sport=RandShort(), dport=80, flags='S')
        for _ in range(150)
    ]
    sendp(pkts, iface=IFACE, verbose=False)
    done(150, 'SYN Flood  |  Severity: HIGH')


def sim_udp_flood():
    """
    UDP Flood — Rule 2
    Sends 600 UDP packets from a public IP in ~1 second.
    Threshold: >500 UDP packets in 5 seconds from public IP → MEDIUM alert.
    """
    banner('UDP FLOOD  (Heuristic — Rule 2)')
    print(f'  Attacker : 198.51.100.20  →  Target : {TARGET_IP}:53')
    print('  Sending 600 UDP packets...')

    pkts = [
        Ether(src=RandMAC(), dst=LOCAL_MAC) /
        IP(src='198.51.100.20', dst=TARGET_IP) /
        UDP(sport=RandShort(), dport=53) /
        Raw(load=b'X' * 64)
        for _ in range(600)
    ]
    sendp(pkts, iface=IFACE, verbose=False)
    done(600, 'UDP Flood  |  Severity: MEDIUM')


def sim_icmp_flood():
    """
    ICMP Flood — Rule 2b
    Sends 400 ICMP echo requests from a public IP.
    Threshold: >300 ICMP packets in 5 seconds from public IP → MEDIUM alert.
    """
    banner('ICMP FLOOD  (Heuristic — Rule 2b)')
    print(f'  Attacker : 198.51.100.30  →  Target : {TARGET_IP}')
    print('  Sending 400 ICMP ping packets...')

    pkts = [
        Ether(src=RandMAC(), dst=LOCAL_MAC) /
        IP(src='198.51.100.30', dst=TARGET_IP) /
        ICMP()
        for _ in range(400)
    ]
    sendp(pkts, iface=IFACE, verbose=False)
    done(400, 'ICMP Flood  |  Severity: MEDIUM')


def sim_port_scan():
    """
    Port Scan — Rule 3
    Sends TCP SYN to 20 different ports from one IP in <1 second.
    Threshold: >10 unique destination ports in 5 seconds → LOW alert.
    """
    banner('PORT SCAN  (Heuristic — Rule 3)')
    ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445,
             3306, 3389, 5432, 6379, 8080, 8443, 27017, 9200, 5900, 1433]
    print(f'  Attacker : 203.0.113.50  →  Target : {TARGET_IP}  ({len(ports)} ports)')
    print(f'  Ports    : {ports}')

    pkts = [
        Ether(src=RandMAC(), dst=LOCAL_MAC) /
        IP(src='203.0.113.50', dst=TARGET_IP) /
        TCP(sport=RandShort(), dport=p, flags='S')
        for p in ports
    ]
    sendp(pkts, iface=IFACE, verbose=False)
    done(len(ports), 'Port Scan  |  Severity: LOW')


def sim_blacklisted_ports():
    """
    Sensitive Port Access — Rule 4
    Connects to blacklisted ports: Telnet, RDP, SMB, Redis, MongoDB.
    Each connection → INFO alert immediately.
    """
    banner('SENSITIVE PORT ACCESS  (Heuristic — Rule 4)')
    targets = [
        (23,    'Telnet'),
        (3389,  'RDP'),
        (445,   'SMB'),
        (6379,  'Redis'),
        (27017, 'MongoDB'),
        (3306,  'MySQL'),
    ]
    print(f'  Attacker : 203.0.113.99  →  Target : {TARGET_IP}')
    for port, name in targets:
        p = Ether(src=RandMAC(), dst=LOCAL_MAC) / IP(src='203.0.113.99', dst=TARGET_IP) / TCP(dport=port, flags='S')
        sendp(p, iface=IFACE, verbose=False)
        print(f'  [+] Sent SYN → port {port} ({name})')
        time.sleep(0.1)
    done(len(targets), 'Sensitive Port Access  |  Severity: INFO  (one alert per port)')


# ── ML Flow Attacks ───────────────────────────────────────────────────────────
# These build BIDIRECTIONAL flows (attacker ↔ target) so FlowTracker produces
# feature vectors that match the CICIDS-2017 training distribution.
# The sniffer captures both directions since sendp() injects at Layer 2.

def _fwd(mac_atk, src_ip, dst_ip, sport, dport, flags, payload=None):
    """Attacker → Target packet (forward direction)."""
    pkt = Ether(src=mac_atk, dst=LOCAL_MAC) / IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    sendp(pkt, iface=IFACE, verbose=False)

def _bwd(mac_atk, src_ip, dst_ip, sport, dport, flags, payload=None):
    """Target → Attacker packet (backward direction — sniffer captures it too)."""
    pkt = Ether(src=LOCAL_MAC, dst=mac_atk) / IP(src=dst_ip, dst=src_ip) / \
          TCP(sport=dport, dport=sport, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    sendp(pkt, iface=IFACE, verbose=False)


def sim_ml_dos():
    """
    ML: DoS HTTP Flood  (DoS Hulk / GoldenEye pattern)
    50 rapid bidirectional HTTP flows to port 80 — each flow completes
    with RST, giving the FlowTracker 50 scored flows.
    Key CICIDS-2017 features: very high Flow Packets/s, many short flows,
    PSH+ACK flags, non-zero bwd packets.
    """
    banner('ML DoS FLOW  (RandomForest classifier)')
    src = '198.51.100.10'
    n_flows = 50
    print(f'  Attacker : {src}  →  {TARGET_IP}:80')
    print(f'  Sending {n_flows} rapid HTTP flows (DoS Hulk pattern)...')

    http_req  = b'GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n'
    http_resp = b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nHELLO!'

    for i in range(n_flows):
        mac = str(RandMAC())
        sport = random.randint(10000, 60000)
        _fwd(mac, src, TARGET_IP, sport, 80, 'S')
        _bwd(mac, src, TARGET_IP, sport, 80, 'SA')
        time.sleep(0.002)
        _fwd(mac, src, TARGET_IP, sport, 80, 'PA', http_req)
        _bwd(mac, src, TARGET_IP, sport, 80, 'PA', http_resp)
        _fwd(mac, src, TARGET_IP, sport, 80, 'R')   # RST closes flow
        if (i + 1) % 10 == 0:
            print(f'  [{i+1}/{n_flows}] flows sent')

    done(n_flows * 5, f'ML: DoS  |  Severity: HIGH  ({n_flows} flows scored)')


def sim_ml_port_scan():
    """
    ML: Port Scan  (nmap SYN scan pattern)
    100 flows each to a different port. Closed ports reply RST-ACK.
    Key CICIDS-2017 features: many unique dst ports, SYN+RST per flow,
    zero PSH/ACK from scanner, very short duration.
    """
    banner('ML PORT SCAN FLOW  (RandomForest classifier)')
    src = '203.0.113.50'
    ports = list(range(20, 120))    # 100 ports
    print(f'  Attacker : {src}  →  {TARGET_IP}  (scanning {len(ports)} ports)')

    for dport in ports:
        mac  = str(RandMAC())
        sport = random.randint(10000, 60000)
        _fwd(mac, src, TARGET_IP, sport, dport, 'S')
        # Target responds RST-ACK for closed port → closes flow immediately
        _bwd(mac, src, TARGET_IP, sport, dport, 'RA')
        time.sleep(0.005)

    done(len(ports) * 2, f'ML: PortScan  |  Severity: LOW  ({len(ports)} flows scored)')


def sim_ml_bruteforce():
    """
    ML: SSH Brute Force  (SSH-Patator pattern)
    15 separate auth-attempt flows to port 22.  Each flow mimics a real
    SSH authentication exchange: handshake → auth data → server challenge
    → failure + RST.
    Key CICIDS-2017 features: SYN:1/flow, high ACK+PSH, ~0.5s duration,
    ~0.5 Down/Up Ratio, bidirectional data.
    """
    banner('ML BRUTE FORCE SSH  (RandomForest classifier)')
    src = '198.51.100.20'
    n_attempts = 15
    print(f'  Attacker : {src}  →  {TARGET_IP}:22  ({n_attempts} auth attempts)')

    ssh_banner  = b'SSH-2.0-OpenSSH_8.9p1\r\n'
    ssh_kexinit = b'\x00' * 20 + b'kexinit_data' + b'\x00' * 20
    ssh_auth    = b'\x00' * 10 + b'password_attempt_' + b'\x00' * 15

    for attempt in range(1, n_attempts + 1):
        mac   = str(RandMAC())
        sport = random.randint(10000, 60000)

        # TCP handshake
        _fwd(mac, src, TARGET_IP, sport, 22, 'S')
        time.sleep(0.04)
        _bwd(mac, src, TARGET_IP, sport, 22, 'SA')
        time.sleep(0.02)
        _fwd(mac, src, TARGET_IP, sport, 22, 'A')

        # SSH banner exchange
        time.sleep(0.05)
        _bwd(mac, src, TARGET_IP, sport, 22, 'PA', ssh_banner)
        time.sleep(0.03)
        _fwd(mac, src, TARGET_IP, sport, 22, 'PA', ssh_banner)

        # Key exchange
        time.sleep(0.05)
        _fwd(mac, src, TARGET_IP, sport, 22, 'PA', ssh_kexinit)
        time.sleep(0.04)
        _bwd(mac, src, TARGET_IP, sport, 22, 'PA', ssh_kexinit)

        # Auth attempt (password)
        time.sleep(0.06)
        _fwd(mac, src, TARGET_IP, sport, 22, 'PA', ssh_auth)
        time.sleep(0.05)
        _bwd(mac, src, TARGET_IP, sport, 22, 'PA', b'\x00\x00\x00\x0cauth_failed')

        # Connection teardown (auth failed → RST)
        time.sleep(0.03)
        _fwd(mac, src, TARGET_IP, sport, 22, 'R')

        print(f'  Attempt {attempt}/{n_attempts}  sport={sport}')
        time.sleep(0.2)   # Brief pause between attempts

    done(n_attempts * 11, f'ML: BruteForce  |  Severity: HIGH  ({n_attempts} flows scored)')


def sim_ml_botnet():
    """
    ML: Botnet C2 Beacon  (periodic check-in pattern)
    8 beacon cycles, each a separate bidirectional TCP flow on port 4444.
    Key CICIDS-2017 features: regular IAT, small payload, bidirectional,
    PSH+FIN flags, non-zero bwd bytes.
    """
    banner('ML BOTNET BEACON  (RandomForest classifier)')
    src    = '198.51.100.30'
    c2_port = 4444
    n_cycles = 8
    print(f'  Bot      : {src}  →  C2:{TARGET_IP}:{c2_port}')
    print(f'  Simulating {n_cycles} beacon cycles (every 3s)...')

    for cycle in range(1, n_cycles + 1):
        mac   = str(RandMAC())
        sport = random.randint(10000, 60000)

        # Handshake
        _fwd(mac, src, TARGET_IP, sport, c2_port, 'S')
        time.sleep(0.05)
        _bwd(mac, src, TARGET_IP, sport, c2_port, 'SA')
        time.sleep(0.03)
        _fwd(mac, src, TARGET_IP, sport, c2_port, 'A')

        # Beacon: bot sends check-in, C2 sends command
        time.sleep(0.05)
        _fwd(mac, src, TARGET_IP, sport, c2_port, 'PA',
             b'\x02BEACON\x00' + bytes([cycle]) + b'\x00' * 8)
        time.sleep(0.06)
        _bwd(mac, src, TARGET_IP, sport, c2_port, 'PA',
             b'\x03CMD\x00SLEEP\x00' + b'\x00' * 6)

        # Teardown
        time.sleep(0.04)
        _fwd(mac, src, TARGET_IP, sport, c2_port, 'FA')
        time.sleep(0.03)
        _bwd(mac, src, TARGET_IP, sport, c2_port, 'FA')

        print(f'  Beacon {cycle}/{n_cycles}  sport={sport}')
        if cycle < n_cycles:
            time.sleep(3)

    done(n_cycles * 8, f'ML: Botnet  |  Severity: CRITICAL  ({n_cycles} flows scored)')


def sim_ml_webattack():
    """
    ML: Web Attack  (XSS / SQLi / path traversal)
    5 bidirectional HTTP flows carrying attack payloads to port 80.
    Key CICIDS-2017 features: PSH+ACK, moderate-sized payloads,
    server 200/400 responses (bwd bytes), short duration.
    """
    banner('ML WEB ATTACK  (RandomForest classifier)')
    src = '203.0.113.99'
    print(f'  Attacker : {src}  →  {TARGET_IP}:80  (web attack payloads)')

    attacks = [
        (b"GET /?id=1' OR '1'='1 HTTP/1.1\r\nHost: target\r\n\r\n",
         b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n" + b'A' * 50),
        (b"GET /?q=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: target\r\n\r\n",
         b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n" + b'B' * 30),
        (b"POST /login HTTP/1.1\r\nHost: target\r\nContent-Length: 35\r\n\r\nusername=admin'--&password=xyz123",
         b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 13\r\n\r\nAccess Denied"),
        (b"GET /?file=../../../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
         b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden"),
        (b"GET /admin?debug=true&cmd=id HTTP/1.1\r\nHost: target\r\n\r\n",
         b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nuid=0(root) .."),
    ]

    for i, (req, resp) in enumerate(attacks):
        mac   = str(RandMAC())
        sport = random.randint(10000, 60000)

        _fwd(mac, src, TARGET_IP, sport, 80, 'S')
        time.sleep(0.03)
        _bwd(mac, src, TARGET_IP, sport, 80, 'SA')
        time.sleep(0.02)
        _fwd(mac, src, TARGET_IP, sport, 80, 'PA', req)
        time.sleep(0.04)
        _bwd(mac, src, TARGET_IP, sport, 80, 'PA', resp)
        time.sleep(0.02)
        _fwd(mac, src, TARGET_IP, sport, 80, 'PA', req)   # second probe
        time.sleep(0.02)
        _fwd(mac, src, TARGET_IP, sport, 80, 'R')          # RST (server kills on error)

        print(f'  [+] Attack {i+1}/{len(attacks)} sent  sport={sport}')
        time.sleep(0.4)

    done(len(attacks) * 6, f'ML: WebAttack  |  Severity: MEDIUM  ({len(attacks)} flows scored)')


# ── Menu ──────────────────────────────────────────────────────────────────────

ATTACKS = {
    # Heuristic
    '1': ('SYN Flood           [Heuristic | HIGH]',     sim_syn_flood),
    '2': ('UDP Flood           [Heuristic | MEDIUM]',   sim_udp_flood),
    '3': ('ICMP Flood          [Heuristic | MEDIUM]',   sim_icmp_flood),
    '4': ('Port Scan           [Heuristic | LOW]',      sim_port_scan),
    '5': ('Sensitive Ports     [Heuristic | INFO]',     sim_blacklisted_ports),
    # ML
    '6': ('DoS Flow            [ML        | HIGH]',     sim_ml_dos),
    '7': ('Port Scan Flow      [ML        | LOW]',      sim_ml_port_scan),
    '8': ('Brute Force SSH     [ML        | HIGH]',     sim_ml_bruteforce),
    '9': ('Botnet Beacon       [ML        | CRITICAL]', sim_ml_botnet),
    '10':('Web Attack          [ML        | MEDIUM]',   sim_ml_webattack),
}


def main():
    parser = argparse.ArgumentParser(description='Sentinels Attack Simulator')
    parser.add_argument('--all', action='store_true', help='Run all simulations sequentially')
    args = parser.parse_args()

    print('\n╔══════════════════════════════════════════════════════╗')
    print('║         SENTINELS  —  Attack Simulator              ║')
    print(f'║         Target: {TARGET_IP:<37}║')
    print('╚══════════════════════════════════════════════════════╝')

    if args.all:
        print('\nRunning ALL attack simulations...\n')
        for key, (label, fn) in ATTACKS.items():
            fn()
            print('  Waiting 6 seconds (heuristic window reset)...')
            time.sleep(6)
        print('\n[✓] All simulations complete. Check Sentinels dashboard.')
        return

    print('\n  ── Heuristic (instant, per-packet) ──────────────────')
    for k in ['1', '2', '3', '4', '5']:
        print(f'  [{k}]  {ATTACKS[k][0]}')

    print('\n  ── ML Classifier (fires when flow completes) ────────')
    for k in ['6', '7', '8', '9', '10']:
        print(f'  [{k}]  {ATTACKS[k][0]}')

    print('\n  [0]  Exit')

    while True:
        choice = input('\nSelect attack [0-10]: ').strip()
        if choice == '0':
            print('Exiting.')
            break
        elif choice in ATTACKS:
            ATTACKS[choice][1]()
        else:
            print('  Invalid choice.')


if __name__ == '__main__':
    main()
