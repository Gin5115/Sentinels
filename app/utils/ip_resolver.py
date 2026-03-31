"""
IP Resolver module for Sentinels.
Provides intelligent IP-to-name resolution with caching.
- Private IPs: Resolved via local hostname lookup
- Public IPs: Resolved via ip-api.com organization lookup
"""

import socket
import ipaddress
import threading
import time
from functools import lru_cache

import requests


class IPResolver:
    """
    Intelligent IP resolver with caching and async resolution.
    Resolves private IPs locally and public IPs via API.
    """
    
    # Cache TTL in seconds (1 hour)
    CACHE_TTL = 3600
    
    # API timeout in seconds
    API_TIMEOUT = 1.0
    
    def __init__(self):
        # Cache: {ip: {'name': str, 'timestamp': float}}
        self._cache = {}
        self._lock = threading.Lock()
        
        # Common private IP prefixes for quick detection
        self._private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ]
    
    def is_private(self, ip: str) -> bool:
        """Check if IP is private/local."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False
    
    def _resolve_local(self, ip: str) -> str:
        """Resolve local/private IP via reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            # Clean up hostname (remove domain suffix if present)
            if '.' in hostname:
                hostname = hostname.split('.')[0]
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            return None
    
    def _resolve_public(self, ip: str) -> str:
        """Resolve public IP via ip-api.com (free, no key required)."""
        try:
            url = f'http://ip-api.com/json/{ip}?fields=status,org,isp'
            response = requests.get(url, timeout=self.API_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    # Prefer org, fallback to isp
                    org = data.get('org') or data.get('isp')
                    if org:
                        # Shorten long org names
                        if len(org) > 20:
                            org = org[:17] + '...'
                        return org
            return None
        except (requests.RequestException, ValueError):
            return None
    
    def resolve(self, ip: str) -> dict:
        """
        Resolve an IP to a human-readable name.
        Returns: {'ip': ip, 'name': 'Resolved Name' or None}
        """
        # Check cache first
        with self._lock:
            cached = self._cache.get(ip)
            if cached:
                # Check TTL
                if time.time() - cached['timestamp'] < self.CACHE_TTL:
                    return {'ip': ip, 'name': cached['name']}
        
        # Resolve based on IP type
        name = None
        if self.is_private(ip):
            name = self._resolve_local(ip)
        else:
            name = self._resolve_public(ip)
        
        # Cache the result (even if None, to avoid repeated lookups)
        with self._lock:
            self._cache[ip] = {
                'name': name,
                'timestamp': time.time()
            }
        
        return {'ip': ip, 'name': name}
    
    def resolve_async(self, ip: str, callback):
        """
        Resolve IP asynchronously in a background thread.
        Calls callback(result) when done.
        """
        def worker():
            result = self.resolve(ip)
            callback(result)
        
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
    
    def get_cached(self, ip: str) -> str:
        """Get cached name for IP, or None if not cached."""
        with self._lock:
            cached = self._cache.get(ip)
            if cached and time.time() - cached['timestamp'] < self.CACHE_TTL:
                return cached['name']
        return None
    
    def get_cached_geo(self, ip: str) -> dict:
        """
        Get cached geo-location for IP WITHOUT making HTTP request.
        Safe for batch lookups (no rate limit risk).
        
        Returns:
            Cached geo dict if found, None otherwise.
            For private IPs, always returns LAN info.
        """
        if not ip:
            return None
        
        # Private IPs always return LAN info (no API needed)
        if self.is_private(ip):
            return {'country': 'LAN', 'city': 'Local Network', 'flag': '💻'}
        
        # Check geo cache only - DO NOT make HTTP request
        cache_key = f"geo:{ip}"
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and time.time() - cached['timestamp'] < self.CACHE_TTL:
                return cached['geo']
        
        # Not in cache - return None (don't trigger API call)
        return None
    
    def resolve_geo(self, ip: str) -> dict:
        """
        Resolve geo-location for an IP address.
        Returns: {'country': str, 'city': str, 'flag': str}
        """
        # Check geo cache first
        cache_key = f"geo:{ip}"
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and time.time() - cached['timestamp'] < self.CACHE_TTL:
                return cached['geo']
        
        # Default result
        geo = {'country': 'Unknown', 'city': 'Unknown', 'flag': '🌐'}
        
        if self.is_private(ip):
            # Private IP - return LAN info
            geo = {'country': 'LAN', 'city': 'Local Network', 'flag': '💻'}
        else:
            # Public IP - query ip-api.com
            try:
                url = f'http://ip-api.com/json/{ip}?fields=status,country,city,countryCode,lat,lon'
                response = requests.get(url, timeout=self.API_TIMEOUT)

                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        country = data.get('country', 'Unknown')
                        city = data.get('city', 'Unknown')
                        country_code = data.get('countryCode', '')

                        # Map common country codes to flag emojis
                        flag_map = {
                            'US': '🇺🇸', 'IN': '🇮🇳', 'CN': '🇨🇳', 'JP': '🇯🇵',
                            'DE': '🇩🇪', 'GB': '🇬🇧', 'FR': '🇫🇷', 'BR': '🇧🇷',
                            'RU': '🇷🇺', 'AU': '🇦🇺', 'CA': '🇨🇦', 'KR': '🇰🇷',
                            'NL': '🇳🇱', 'SG': '🇸🇬', 'IE': '🇮🇪', 'SE': '🇸🇪'
                        }
                        flag = flag_map.get(country_code, '🌐')

                        geo = {
                            'country': country, 'city': city, 'flag': flag,
                            'lat': data.get('lat'), 'lon': data.get('lon')
                        }
            except (requests.RequestException, ValueError):
                pass
        
        # Cache the result
        with self._lock:
            self._cache[cache_key] = {
                'geo': geo,
                'timestamp': time.time()
            }
        
        return geo
    
    def resolve_geo_async(self, ip: str, callback):
        """Resolve geo-location asynchronously."""
        def worker():
            result = self.resolve_geo(ip)
            result['ip'] = ip
            callback(result)
        
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
    
    def clear_cache(self):
        """Clear the resolver cache."""
        with self._lock:
            self._cache.clear()


# Global singleton instance
_resolver_instance = None


def get_resolver() -> IPResolver:
    """Get the global IPResolver instance."""
    global _resolver_instance
    if _resolver_instance is None:
        _resolver_instance = IPResolver()
    return _resolver_instance
