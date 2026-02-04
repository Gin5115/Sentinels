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
    
    # Detection thresholds (realistic values for normal networks)
    SYN_FLOOD_THRESHOLD = 100      # SYN packets per 5 seconds
    UDP_FLOOD_THRESHOLD = 500      # UDP packets per 5 seconds (raised to avoid false positives)
    PORT_SCAN_THRESHOLD = 10       # Unique ports per 5 seconds
    
    # Blacklisted ports (commonly targeted by attackers)
    BLACKLISTED_PORTS = {
        23: 'Telnet',
        3389: 'RDP',
        445: 'SMB',
        22: 'SSH',
        1433: 'MSSQL',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB'
    }
    
    # Severity levels
    SEVERITY_CRITICAL = 'Critical'
    SEVERITY_HIGH = 'High'
    SEVERITY_MEDIUM = 'Medium'
    SEVERITY_LOW = 'Low'
    SEVERITY_INFO = 'Info'
    
    def __init__(self):
        self._lock = threading.Lock()
        
        # Tracking dictionaries (reset every window)
        self._syn_track = defaultdict(int)    # {ip: count}
        self._udp_track = defaultdict(int)    # {ip: count}
        self._scan_track = defaultdict(set)   # {ip: set(ports)}
        
        # Time window tracking
        self._window_start = time.time()
        self._window_duration = 5.0  # 5 second window (extended for testing)
        
        # Threat history (prevent duplicate alerts)
        self._recent_alerts = {}  # {threat_key: timestamp}
        self._alert_cooldown = 5.0  # seconds
        
        # Debug flag
        self._debug = True
    
    def _reset_window(self):
        """Reset tracking counters for new time window."""
        with self._lock:
            self._syn_track.clear()
            self._udp_track.clear()
            self._scan_track.clear()
            self._window_start = time.time()
    
    def _should_alert(self, threat_key: str) -> bool:
        """Check if we should emit alert (prevent spam)."""
        now = time.time()
        with self._lock:
            last_alert = self._recent_alerts.get(threat_key, 0)
            if now - last_alert > self._alert_cooldown:
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
        if now - self._window_start > self._window_duration:
            self._reset_window()
        
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        protocol = packet_data.get('protocol', '').upper()
        flags = packet_data.get('flags', '')
        dst_port = packet_data.get('dst_port')
        
        if not src_ip:
            return None
        
        # === Rule 1: SYN Flood Detection ===
        if protocol == 'TCP' and 'S' in str(flags) and 'A' not in str(flags):
            with self._lock:
                self._syn_track[src_ip] += 1
                syn_count = self._syn_track[src_ip]
            
            if syn_count > self.SYN_FLOOD_THRESHOLD:
                threat_key = f"syn_flood:{src_ip}"
                if self._should_alert(threat_key):
                    return {
                        'type': 'SYN Flood',
                        'ip': src_ip,
                        'severity': self.SEVERITY_HIGH,
                        'description': f'High volume SYN requests ({syn_count}/s) from {src_ip}',
                        'count': syn_count
                    }
        
        # === Rule 2: UDP Flood Detection ===
        # Skip flood detection for private/local IPs (normal LAN traffic)
        is_private = (
            src_ip.startswith('192.168.') or 
            src_ip.startswith('10.') or 
            src_ip.startswith('172.16.') or
            src_ip.startswith('172.17.') or
            src_ip.startswith('172.18.') or
            src_ip.startswith('fe80:') or  # IPv6 link-local
            src_ip.startswith('fd') or     # IPv6 private
            src_ip == '127.0.0.1' or
            src_ip == '::1'
        )
        
        if protocol == 'UDP' and not is_private:
            with self._lock:
                self._udp_track[src_ip] += 1
                udp_count = self._udp_track[src_ip]
            
            if udp_count > self.UDP_FLOOD_THRESHOLD:
                threat_key = f"udp_flood:{src_ip}"
                if self._should_alert(threat_key):
                    return {
                        'type': 'UDP Flood',
                        'ip': src_ip,
                        'severity': self.SEVERITY_MEDIUM,
                        'description': f'High volume UDP traffic ({udp_count}/5s) from {src_ip}',
                        'count': udp_count
                    }
        
        # === Rule 3: Port Scan Detection ===
        if dst_port:
            with self._lock:
                self._scan_track[src_ip].add(dst_port)
                port_count = len(self._scan_track[src_ip])
            
            # Debug: log port scan progress
            if self._debug and port_count % 5 == 0:
                print(f'[ThreatEngine] Port scan tracking: {src_ip} -> {port_count} unique ports (threshold: {self.PORT_SCAN_THRESHOLD})')
            
            if port_count > self.PORT_SCAN_THRESHOLD:
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
        if dst_port in self.BLACKLISTED_PORTS:
            service = self.BLACKLISTED_PORTS[dst_port]
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
                'scan_track_count': len(self._scan_track),
                'recent_alerts': len(self._recent_alerts)
            }
    
    def clear(self):
        """Clear all tracking data."""
        with self._lock:
            self._syn_track.clear()
            self._udp_track.clear()
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
