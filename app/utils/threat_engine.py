"""
Threat Detection Engine for Sentinels.
Implements heuristic-based detection for common network attacks:
- SYN Flood (>100 SYN packets/sec from single IP)
- UDP Flood (>200 UDP packets/sec from single IP)
- Port Scan (>15 unique ports targeted by single IP)
- Blacklisted Ports (Telnet, RDP, SMB)
"""

import time
import threading
from collections import defaultdict


class ThreatEngine:
    """
    Heuristic threat detection engine.
    Analyzes packets in real-time to detect suspicious activity.
    """

    # Severity levels
    SEVERITY_CRITICAL = 'Critical'
    SEVERITY_HIGH = 'High'
    SEVERITY_MEDIUM = 'Medium'
    SEVERITY_LOW = 'Low'
    SEVERITY_INFO = 'Info'

    def __init__(self):
        self._lock = threading.Lock()

        # Adjustable thresholds (can be changed at runtime via Settings)
        self.syn_flood_threshold  = 100   # SYN packets per window
        self.udp_flood_threshold  = 500   # UDP packets per window
        self.icmp_flood_threshold = 300   # ICMP packets per window
        self.port_scan_threshold  = 10    # unique destination ports per window
        self.window_duration      = 5.0   # seconds per detection window
        self.alert_cooldown       = 5.0   # seconds between repeated alerts

        # Blacklisted ports
        self.blacklisted_ports = {
            23: 'Telnet', 3389: 'RDP', 445: 'SMB', 22: 'SSH',
            1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL',
            6379: 'Redis', 27017: 'MongoDB',
        }

        # Tracking dictionaries (reset every window)
        self._syn_track  = defaultdict(int)
        self._udp_track  = defaultdict(int)
        self._icmp_track = defaultdict(int)
        self._scan_track = defaultdict(set)

        # Time window tracking
        self._window_start = time.time()

        # Threat history (prevent duplicate alerts)
        self._recent_alerts = {}

        # Debug flag
        self._debug = True

    # ── threshold management ──────────────────────────────────────────────────

    def get_thresholds(self) -> dict:
        with self._lock:
            return {
                'syn_flood_threshold':  self.syn_flood_threshold,
                'udp_flood_threshold':  self.udp_flood_threshold,
                'icmp_flood_threshold': self.icmp_flood_threshold,
                'port_scan_threshold':  self.port_scan_threshold,
                'window_duration':      self.window_duration,
                'alert_cooldown':       self.alert_cooldown,
            }

    def set_thresholds(self, values: dict) -> dict:
        """Update one or more thresholds. Returns the new state."""
        int_keys   = ('syn_flood_threshold', 'udp_flood_threshold',
                      'icmp_flood_threshold', 'port_scan_threshold')
        float_keys = ('window_duration', 'alert_cooldown')
        with self._lock:
            for k in int_keys:
                if k in values:
                    v = int(values[k])
                    if v > 0:
                        setattr(self, k, v)
            for k in float_keys:
                if k in values:
                    v = float(values[k])
                    if v > 0:
                        setattr(self, k, v)
        return self.get_thresholds()
    
    def _reset_window(self):
        """Reset tracking counters for new time window."""
        with self._lock:
            self._syn_track.clear()
            self._udp_track.clear()
            self._icmp_track.clear()
            self._scan_track.clear()
            self._window_start = time.time()

    def _should_alert(self, threat_key: str) -> bool:
        """Check if we should emit alert (prevent spam)."""
        now = time.time()
        with self._lock:
            last_alert = self._recent_alerts.get(threat_key, 0)
            if now - last_alert > self.alert_cooldown:
                self._recent_alerts[threat_key] = now
                return True
        return False
    
    def analyze_packet(self, packet_data: dict) -> dict:
        """
        Analyze a packet for potential threats.
        
        Args:
            packet_data: Dictionary containing packet info:
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - protocol: Protocol name (TCP, UDP, etc.)
                - flags: TCP flags (if applicable)
                - dst_port: Destination port (if applicable)
        
        Returns:
            Threat dict if detected, None otherwise.
            Threat: {'type': str, 'ip': str, 'severity': str, 'description': str}
        """
        now = time.time()
        
        # Reset window if expired
        if now - self._window_start > self.window_duration:
            self._reset_window()
        
        src_ip   = packet_data.get('src_ip')
        dst_ip   = packet_data.get('dst_ip')
        protocol = packet_data.get('protocol', '').upper()
        flags    = packet_data.get('flags', '')
        dst_port = packet_data.get('dst_port')
        src_port = packet_data.get('src_port')

        if not src_ip:
            return None

        # IPs to exclude from flood/scan detection:
        #   - RFC-1918 private ranges and link-local (normal LAN traffic)
        #   - Well-known public DNS resolvers (their responses hit many ephemeral ports)
        #   - Major CDN/cloud providers that serve QUIC (UDP) at high volume
        _TRUSTED_PUBLIC = {
            '8.8.8.8', '8.8.4.4',          # Google DNS
            '1.1.1.1', '1.0.0.1',           # Cloudflare DNS
            '9.9.9.9', '149.112.112.112',   # Quad9 DNS
            '208.67.222.222', '208.67.220.220',  # OpenDNS
        }
        is_private = (
            src_ip.startswith('192.168.') or
            src_ip.startswith('10.') or
            src_ip.startswith('172.16.') or src_ip.startswith('172.17.') or
            src_ip.startswith('172.18.') or src_ip.startswith('172.19.') or
            src_ip.startswith('172.20.') or src_ip.startswith('172.21.') or
            src_ip.startswith('172.22.') or src_ip.startswith('172.23.') or
            src_ip.startswith('172.24.') or src_ip.startswith('172.25.') or
            src_ip.startswith('172.26.') or src_ip.startswith('172.27.') or
            src_ip.startswith('172.28.') or src_ip.startswith('172.29.') or
            src_ip.startswith('172.30.') or src_ip.startswith('172.31.') or
            src_ip.startswith('fe80:') or src_ip.startswith('fd') or
            src_ip in ('127.0.0.1', '::1') or
            src_ip in _TRUSTED_PUBLIC
        )
        # DNS response packets (src_port=53) hitting different client ports
        # look like a port scan — skip them from scan tracking
        is_dns_response = (src_port == 53)

        # === Rule 1: SYN Flood Detection ===
        if protocol == 'TCP' and 'S' in str(flags) and 'A' not in str(flags):
            with self._lock:
                self._syn_track[src_ip] += 1
                syn_count = self._syn_track[src_ip]

            if syn_count > self.syn_flood_threshold:
                threat_key = f"syn_flood:{src_ip}"
                if self._should_alert(threat_key):
                    return {
                        'type': 'SYN Flood',
                        'ip': src_ip,
                        'severity': self.SEVERITY_HIGH,
                        'description': f'High volume SYN requests ({syn_count}/window) from {src_ip}',
                        'count': syn_count
                    }

        # === Rule 2: UDP Flood Detection ===
        if protocol == 'UDP' and not is_private:
            with self._lock:
                self._udp_track[src_ip] += 1
                udp_count = self._udp_track[src_ip]

            if udp_count > self.udp_flood_threshold:
                threat_key = f"udp_flood:{src_ip}"
                if self._should_alert(threat_key):
                    return {
                        'type': 'UDP Flood',
                        'ip': src_ip,
                        'severity': self.SEVERITY_MEDIUM,
                        'description': f'High volume UDP traffic ({udp_count}/{int(self.window_duration)}s) from {src_ip}',
                        'count': udp_count
                    }

        # === Rule 2b: ICMP Flood Detection ===
        if protocol == 'ICMP' and not is_private:
            with self._lock:
                self._icmp_track[src_ip] += 1
                icmp_count = self._icmp_track[src_ip]

            if icmp_count > self.icmp_flood_threshold:
                threat_key = f"icmp_flood:{src_ip}"
                if self._should_alert(threat_key):
                    return {
                        'type': 'ICMP Flood',
                        'ip': src_ip,
                        'severity': self.SEVERITY_MEDIUM,
                        'description': f'High volume ICMP traffic ({icmp_count}/{int(self.window_duration)}s) from {src_ip}',
                        'count': icmp_count
                    }

        # === Rule 3: Port Scan Detection ===
        # Skip DNS response packets and private/trusted IPs
        if dst_port and not is_private and not is_dns_response:
            with self._lock:
                self._scan_track[src_ip].add(dst_port)
                port_count = len(self._scan_track[src_ip])
            
            if port_count > self.port_scan_threshold:
                threat_key = f"port_scan:{src_ip}"
                if self._should_alert(threat_key):
                    print(f'[ThreatEngine] ⚠️ THREAT DETECTED: Port Scan from {src_ip} ({port_count} ports)')
                    return {
                        'type': 'Port Scan',
                        'ip': src_ip,
                        'severity': self.SEVERITY_LOW,
                        'description': f'Scanning multiple ports ({port_count} ports) from {src_ip}',
                        'count': port_count
                    }
        
        # === Rule 4: Blacklisted Port Access ===
        if dst_port in self.blacklisted_ports:
            service = self.blacklisted_ports[dst_port]
            threat_key = f"blacklist:{src_ip}:{dst_port}"
            if self._should_alert(threat_key):
                return {
                    'type': 'Sensitive Port Access',
                    'ip': src_ip,
                    'severity': self.SEVERITY_INFO,
                    'description': f'Access to {service} (port {dst_port}) from {src_ip}',
                    'port': dst_port,
                    'service': service
                }
        
        return None
    
    def get_stats(self) -> dict:
        """Get current detection statistics."""
        with self._lock:
            return {
                'syn_track_count': len(self._syn_track),
                'udp_track_count': len(self._udp_track),
                'icmp_track_count': len(self._icmp_track),
                'scan_track_count': len(self._scan_track),
                'recent_alerts': len(self._recent_alerts)
            }
    
    def clear(self):
        """Clear all tracking data."""
        with self._lock:
            self._syn_track.clear()
            self._udp_track.clear()
            self._icmp_track.clear()
            self._scan_track.clear()
            self._recent_alerts.clear()
            self._window_start = time.time()


# Global singleton instance
_threat_engine_instance = None


def get_threat_engine() -> ThreatEngine:
    """Get the global ThreatEngine instance."""
    global _threat_engine_instance
    if _threat_engine_instance is None:
        _threat_engine_instance = ThreatEngine()
    return _threat_engine_instance
