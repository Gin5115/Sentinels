"""
Traffic Statistics Manager for Sentinels.
Provides thread-safe persistent counting of packets per IP.
Persists across page refreshes since data lives on the server.
"""

import threading
from collections import Counter


class TrafficStats:
    """
    Singleton-style traffic statistics tracker.
    Thread-safe counting of packets per source IP.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._counts = Counter()  # {ip: packet_count}
        self._protocol_counts = Counter()  # {ip: {protocol: count}}
    
    def update(self, ip: str, protocol: str = None):
        """
        Thread-safe increment of packet count for an IP.
        
        Args:
            ip: Source or destination IP address
            protocol: Protocol name (TCP, UDP, etc.)
        """
        if not ip:
            return
        
        with self._lock:
            self._counts[ip] += 1
            
            # Track protocol breakdown per IP
            if protocol:
                key = f"{ip}:{protocol}"
                self._protocol_counts[key] += 1
    
    def get_top(self, limit: int = 5) -> list:
        """
        Get top IPs by packet count.
        
        Args:
            limit: Number of top IPs to return
            
        Returns:
            List of dicts: [{'ip': x, 'count': y}, ...]
        """
        with self._lock:
            top = self._counts.most_common(limit)
        
        return [{'ip': ip, 'count': count} for ip, count in top]
    
    def get_all(self) -> list:
        """
        Get ALL IPs sorted by count (descending).
        
        Returns:
            List of dicts: [{'ip': x, 'count': y}, ...]
        """
        with self._lock:
            all_ips = self._counts.most_common()
        
        return [{'ip': ip, 'count': count} for ip, count in all_ips]
    
    def get_ip_protocols(self, ip: str) -> dict:
        """
        Get protocol breakdown for a specific IP.
        
        Args:
            ip: IP address to query
            
        Returns:
            Dict of protocol counts: {'TCP': 50, 'UDP': 30, ...}
        """
        result = {}
        prefix = f"{ip}:"
        
        with self._lock:
            for key, count in self._protocol_counts.items():
                if key.startswith(prefix):
                    protocol = key[len(prefix):]
                    result[protocol] = count
        
        return result
    
    def get_count(self, ip: str) -> int:
        """Get packet count for a specific IP."""
        with self._lock:
            return self._counts.get(ip, 0)
    
    def clear(self):
        """Clear all statistics."""
        with self._lock:
            self._counts.clear()
            self._protocol_counts.clear()
    
    def total_packets(self) -> int:
        """Get total packet count across all IPs."""
        with self._lock:
            return sum(self._counts.values())


# Global singleton instance
traffic_stats = TrafficStats()
