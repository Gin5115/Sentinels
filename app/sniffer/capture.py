"""
Packet capture module using Scapy.
Requires libpcap on Linux/macOS or Npcap on Windows.
Supports both IPv4 and IPv6 traffic.
"""
import sys
import threading
import psutil
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, Ether, Raw, conf

from app.utils.stats_manager import traffic_stats
from app.utils.threat_engine import get_threat_engine
from app.utils.ip_resolver import get_resolver


def detect_threats(packet_data):
    """
    Simple rule-based threat detection.
    Returns dict with 'type' if threat detected, else None.
    """
    # Potential SYN Scan: TCP + SYN flag + Small size
    if packet_data.get('protocol') == 'TCP':
        flags = packet_data.get('flags', '')
        length = packet_data.get('len', 0)
        # Check if exactly SYN (S) or contains SYN
        # Scapy flags are string representations. 'S' is SYN.
        if flags == 'S' and length < 60:
             return {'type': 'Potential SYN Scan'}
    return None


def _get_if_list():
    """Cross-platform replacement for get_windows_if_list().
    Returns list of dicts with keys: name, description, ips."""
    result = []
    for name, addr_list in psutil.net_if_addrs().items():
        ips = [
            a.address for a in addr_list
            if a.family.name in ('AF_INET', 'AF_INET6')
        ]
        result.append({'name': name, 'description': name, 'ips': ips})
    return result


class PacketSniffer:
    """
    A threaded packet sniffer using Scapy.
    Captures network traffic and emits packet data via a callback function.
    """
    
    # Protocol number to name mapping (same for IPv4 and IPv6)
    # Reference: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    PROTOCOL_MAP = {
        0: 'HOPOPT',    # IPv6 Hop-by-Hop Option
        1: 'ICMP',      # ICMPv4
        2: 'IGMP',      # Internet Group Management
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',      # Generic Routing Encapsulation
        50: 'ESP',      # Encapsulating Security Payload
        51: 'AH',       # Authentication Header
        58: 'ICMPv6',   # ICMPv6
    }
    
    def __init__(self, callback_func):
        """
        Initialize the packet sniffer.
        
        Args:
            callback_func: Function to call with packet data.
                          This will be used to send data to the UI.
        """
        self.callback_func = callback_func
        self._stop_flag = threading.Event()
        self._thread = None
        self._interface = None
        self._packet_count = 0
    
    def _packet_callback(self, packet):
        """
        Process captured packets and extract relevant information.
        Supports both IPv4 and IPv6 packets.
        
        Args:
            packet: Scapy packet object
        """
        self._packet_count += 1
        
        # Log every packet for debugging (first 10 only)
        if self._packet_count <= 10:
            print(f'[Sniffer] Packet #{self._packet_count}: {packet.summary()[:80]}')
        elif self._packet_count == 11:
            print('[Sniffer] (Suppressing further packet logs...)')
        
        # Determine IP version and extract layer
        ip_layer = None
        ip_version = None
        
        if IP in packet:
            ip_layer = packet[IP]
            ip_version = 4
            # Skip IPv4 loopback and invalid addresses
            skip_ips_v4 = {'127.0.0.1', '0.0.0.0', '255.255.255.255'}
            if ip_layer.src in skip_ips_v4 or ip_layer.dst in skip_ips_v4:
                return
        elif IPv6 in packet:
            ip_layer = packet[IPv6]
            ip_version = 6
            # Skip IPv6 loopback and link-local multicast (optional filtering)
            if ip_layer.src == '::1' or ip_layer.dst == '::1':
                return
        else:
            # Not an IP packet (ARP, etc.) - skip
            return
        
        # Extract MAC address from Ethernet layer if present
        mac_src = None
        mac_dst = None
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
        
        # Get protocol number (nh = next header for IPv6, proto for IPv4)
        proto_num = ip_layer.nh if ip_version == 6 else ip_layer.proto
        protocol_name = self.PROTOCOL_MAP.get(proto_num, str(proto_num))
        
        # Extract basic packet information
        packet_data = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': protocol_name,
            'ip_version': ip_version,
            'len': len(packet),
            'mac_src': mac_src,
            'mac_dst': mac_dst,
            'threat': None,
            'threat_type': None
        }
        
        # Threat detection logic
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_data['src_port'] = tcp_layer.sport
            packet_data['dst_port'] = tcp_layer.dport
            packet_data['flags'] = str(tcp_layer.flags)
        
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_data['src_port'] = udp_layer.sport
            packet_data['dst_port'] = udp_layer.dport
            
        # Run threat detection
        threat_result = detect_threats(packet_data)
        
        if threat_result:
            packet_data['is_threat'] = True
            packet_data['threat_type'] = threat_result['type']
            # Legacy support
            packet_data['threat'] = True
        else:
            packet_data['is_threat'] = False
            packet_data['threat_type'] = 'Normal'
            packet_data['threat'] = False
        
        # Extract payload data
        payload = ''
        if Raw in packet:
            try:
                raw_bytes = bytes(packet[Raw].load)
                
                # Attempt custom "Pretty Print" for mixed content
                try:
                    # 1. Try strict UTF-8 first
                    decoded = raw_bytes.decode('utf-8', errors='strict')
                    
                    # If strictly valid UTF-8, check if it actually looks like text (no weird control chars)
                    # We allow common whitespace (\n \r \t) but reject other low control codes
                    is_clean_text = all(c.isprintable() or c in '\n\r\t' for c in decoded)
                    
                    if is_clean_text:
                        payload = decoded
                    else:
                        raise ValueError("Contains control characters")

                except (UnicodeDecodeError, ValueError):
                    # 2. Fallback: Check if it's "mostly" text (e.g. HTTP with some binary headers)
                    # We use a looser decode for analysis
                    loose_decoded = raw_bytes.decode('utf-8', errors='replace')
                    printable_count = sum(1 for c in loose_decoded if c.isprintable() or c in '\n\r\t')
                    ratio = printable_count / max(len(loose_decoded), 1)
                    
                    if ratio > 0.90:  # Strict 90% threshold (was 0.7)
                        payload = loose_decoded
                    else:
                        # 3. It's binary/encrypted. Return readable HEX.
                        # Format: "Hex: 1A 2B 3C ..." for better readability
                        hex_str = raw_bytes[:50].hex()
                        # Insert space every 2 chars
                        payload = 'Hex: ' + ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2)).upper()
                
                # Limit length for display
                if len(payload) > 200:
                    payload = payload[:200] + '...'
            except Exception:
                payload = '[Error extracting payload]'
        packet_data['payload'] = payload
        
        # Update traffic stats (backend persistence)
        traffic_stats.update(packet_data.get('src_ip'), packet_data.get('protocol'))
        traffic_stats.update(packet_data.get('dst_ip'), packet_data.get('protocol'))
        
        # Heuristic threat detection (ThreatEngine)
        threat_engine = get_threat_engine()
        heuristic_threat = threat_engine.analyze_packet(packet_data)
        
        if heuristic_threat:
            # Enrich with geo-location
            resolver = get_resolver()
            geo = resolver.resolve_geo(heuristic_threat['ip'])
            heuristic_threat['location'] = geo.get('country', 'Unknown')
            heuristic_threat['city'] = geo.get('city', 'Unknown')
            heuristic_threat['flag'] = geo.get('flag', '🌐')
            heuristic_threat['timestamp'] = packet_data.get('timestamp')
            
            # Persist threat to database for Threat Logs page
            from app.models.threat import log_threat
            log_threat(
                source_ip=heuristic_threat.get('ip'),
                destination_ip=packet_data.get('dst_ip'),
                protocol=packet_data.get('protocol'),
                threat_type=heuristic_threat.get('type'),
                severity=heuristic_threat.get('severity', 'Medium').upper(),
                description=heuristic_threat.get('description'),
                packet_size=packet_data.get('len'),
                payload=packet_data.get('payload')
            )
            
            # Emit threat alert via callback (will be handled by socket_events)
            packet_data['heuristic_threat'] = heuristic_threat
        
        # Pass packet data to the callback function
        if self.callback_func:
            self.callback_func(packet_data)
    
    def _sniff_packets(self):
        """
        Internal method that runs the Scapy sniffer.
        Executed in a separate daemon thread.
        """
        print(f'[Sniffer] Thread started on interface: {self._interface or "ALL"}')
        print(f'[Sniffer] Scapy default iface: {conf.iface}')
        
        try:
            # Run sniff with stop condition checking the stop flag
            sniff(
                iface=self._interface,
                prn=self._packet_callback,
                store=False,  # Don't store packets in memory
                stop_filter=lambda x: self._stop_flag.is_set()
            )
            print('[Sniffer] Sniff loop ended normally')
        except PermissionError as e:
            print(f'[Sniffer] ✗ PERMISSION ERROR: {e}')
            print('[Sniffer] → Run with sudo (Linux/macOS) or as Administrator (Windows)!')
            error_data = {
                'timestamp': datetime.now().isoformat(),
                'error': 'Permission denied - Run as Administrator',
                'threat': None,
                'threat_type': 'Permission Error'
            }
            if self.callback_func:
                self.callback_func(error_data)
        except Exception as e:
            print(f'[Sniffer] ✗ ERROR in sniff thread: {type(e).__name__}: {e}')
            import traceback
            traceback.print_exc()
            error_data = {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'threat': None,
                'threat_type': 'Sniffer Error'
            }
            if self.callback_func:
                self.callback_func(error_data)
    
    def start(self, interface=None):
        """
        Start the packet sniffer in a background daemon thread.
        
        Args:
            interface: Network interface to sniff on.
                      If None, will attempt to auto-detect active interface.
        """
        # Safety check: prevent duplicate threads
        if self.is_running():
            print('[Sniffer] Already running, ignoring start request')
            return False
        
        self._stop_flag.clear()
        self._packet_count = 0
        
        # Auto-detect active interface if not specified
        if interface is None:
            interface = self._detect_active_interface()
        
        self._interface = interface
        print(f'[Sniffer] Selected interface: {self._interface}')
        
        # Create and start daemon thread
        self._thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self._thread.start()
        
        return True
    
    def _detect_active_interface(self):
        """
        Attempt to detect the active network interface.
        Prioritizes Wi-Fi over Ethernet on laptops.
        """
        try:
            interfaces = _get_if_list()
            
            # Skip these virtual/inactive interfaces
            skip_keywords = ['virtual', 'loopback', 'bluetooth', 'vmware', 'virtualbox', 'hyper-v', 'pseudo']
            
            # Priority order: Wi-Fi first, then Ethernet
            priority_order = [
                ['wi-fi', 'wifi', 'wireless', 'wlan'],  # Wi-Fi keywords (highest priority)
                ['ethernet', 'eth', 'gbe', 'gigabit']   # Ethernet keywords
            ]
            
            for priority_keywords in priority_order:
                for iface in interfaces:
                    name = iface.get('name', '').lower()
                    desc = iface.get('description', '').lower()
                    ips = iface.get('ips', [])
                    
                    # Skip interfaces without IPs or with skip keywords
                    if not ips:
                        continue
                    if any(skip in name or skip in desc for skip in skip_keywords):
                        continue
                    
                    # Check for valid IPv4 (not link-local 169.254.x.x)
                    has_valid_ipv4 = any(
                        not ip.startswith('fe80') and 
                        not ip.startswith('169.254') and 
                        ':' not in ip and
                        ip != '0.0.0.0'
                        for ip in ips
                    )
                    
                    if has_valid_ipv4 and any(kw in name or kw in desc for kw in priority_keywords):
                        print(f'[Sniffer] Auto-detected interface: {iface.get("name")} - IPs: {ips[:2]}')
                        return iface.get('name')
            
            # Final fallback: any interface with a valid IP
            for iface in interfaces:
                ips = iface.get('ips', [])
                name = iface.get('name', '').lower()
                desc = iface.get('description', '').lower()
                
                if any(skip in name or skip in desc for skip in skip_keywords):
                    continue
                    
                has_valid_ipv4 = any(
                    not ip.startswith('fe80') and
                    not ip.startswith('169.254') and
                    ':' not in ip
                    for ip in ips
                )
                if has_valid_ipv4:
                    print(f'[Sniffer] Fallback interface: {iface.get("name")}')
                    return iface.get('name')
                    
        except Exception as e:
            print(f'[Sniffer] Error detecting interface: {e}')
        
        return None  # Let Scapy use default
    
    def stop(self):
        """
        Stop the packet sniffer cleanly by setting the stop flag.
        """
        if not self.is_running():
            print('[Sniffer] Not running, ignoring stop request')
            return False
        
        print('[Sniffer] Stopping...')
        self._stop_flag.set()
        
        # Give the thread a moment to clean up
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        
        self._thread = None
        print('[Sniffer] Stopped')
        return True
    
    def is_running(self):
        """Check if the sniffer is currently running."""
        return self._thread is not None and self._thread.is_alive()
    
    @staticmethod
    def get_available_interfaces():
        """
        Get a list of available network interfaces on Windows.
        
        Returns:
            List of dictionaries containing interface information.
        """
        try:
            interfaces = _get_if_list()
            return [
                {
                    'name': iface.get('name', 'Unknown'),
                    'description': iface.get('description', ''),
                    'ips': iface.get('ips', [])
                }
                for iface in interfaces
            ]
        except Exception:
            return []
