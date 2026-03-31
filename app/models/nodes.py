"""
Node statistics tracking for Active Nodes page.
Tracks packet counts, bandwidth, and device fingerprinting per source IP.

Uses background threading for slow operations (DNS, MAC lookup) to avoid
blocking the packet capture stream.
"""
import socket
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Thread pool for background metadata resolution
_executor = ThreadPoolExecutor(max_workers=4)

# MAC Vendor Lookup - initialized once at module level
_mac_lookup = None
try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    # Update vendor database in background (non-blocking — download can hang without internet)
    def _update_vendors():
        try:
            _mac_lookup.update_vendors()
            print('[Nodes] MAC vendor database updated')
        except Exception:
            print('[Nodes] Using cached MAC vendor database')
    import threading as _threading
    _threading.Thread(target=_update_vendors, daemon=True).start()
except ImportError:
    print('[Nodes] mac-vendor-lookup not installed, vendor lookup disabled')


# Global dictionary to store node statistics
# Key: IP address, Value: dict with stats
NODE_STATS = {}

# Track IPs that are currently being resolved
_resolving = set()


def _lookup_vendor(mac_address):
    """
    Look up the vendor name for a MAC address.
    Thread-safe, uses global _mac_lookup.
    """
    if not _mac_lookup or not mac_address:
        return 'Unknown'
    
    try:
        vendor = _mac_lookup.lookup(mac_address)
        return vendor if vendor else 'Unknown'
    except Exception:
        return 'Unknown'


def _resolve_hostname(ip_address):
    """
    Attempt to resolve hostname for an IP address.
    This can be slow, hence run in background thread.
    """
    if not ip_address:
        return None
    
    try:
        # Try getfqdn first (usually faster)
        hostname = socket.getfqdn(ip_address)
        
        # If getfqdn returns the IP itself, try gethostbyaddr
        if hostname == ip_address:
            try:
                socket.setdefaulttimeout(2.0)  # 2 second timeout
                hostname = socket.gethostbyaddr(ip_address)[0]
            except (socket.herror, socket.gaierror, socket.timeout):
                hostname = None
            finally:
                socket.setdefaulttimeout(None)
        
        return hostname if hostname and hostname != ip_address else None
    except Exception:
        return None


def _resolve_metadata(ip, mac):
    """
    Background task to resolve vendor and hostname.
    Updates NODE_STATS directly once resolution completes.
    """
    try:
        # Perform slow lookups
        vendor = _lookup_vendor(mac) if mac else 'Unknown'
        hostname = _resolve_hostname(ip)
        
        # Update the node stats if it still exists
        if ip in NODE_STATS:
            NODE_STATS[ip]['vendor'] = vendor
            NODE_STATS[ip]['hostname'] = hostname
    except Exception as e:
        print(f'[Nodes] Error resolving metadata for {ip}: {e}')
    finally:
        # Remove from resolving set
        _resolving.discard(ip)


def update_node_stats(src_ip, packet_size, mac_address=None):
    """
    Update statistics for a source IP address.
    Only tracks private/local network IPs to avoid cluttering with public internet IPs.
    Fast path - never blocks on DNS or MAC lookups.
    
    Args:
        src_ip: Source IP address
        packet_size: Size of the packet in bytes
        mac_address: Source MAC address (optional)
    """
    if not src_ip:
        return
    
    # Filter: Only track private/local network IPs
    try:
        ip = ipaddress.ip_address(src_ip)
        # Skip public IPs (internet addresses)
        if not ip.is_private:
            return
        # Skip loopback and unspecified addresses
        if ip.is_loopback or ip.is_unspecified:
            return
    except ValueError:
        # Invalid IP format, skip it
        return
    
    timestamp = datetime.now().isoformat()
    
    if src_ip not in NODE_STATS:
        # New node - add immediately with placeholder values
        NODE_STATS[src_ip] = {
            'ip': src_ip,
            'mac': mac_address,
            'vendor': 'Resolving...',
            'hostname': None,
            'packets': 0,
            'bytes': 0,
            'first_seen': timestamp,
            'last_seen': timestamp
        }
        
        # Submit background task for metadata resolution (only once per IP)
        if src_ip not in _resolving:
            _resolving.add(src_ip)
            _executor.submit(_resolve_metadata, src_ip, mac_address)
    
    else:
        # Existing node - update MAC if we didn't have it
        if mac_address and not NODE_STATS[src_ip].get('mac'):
            NODE_STATS[src_ip]['mac'] = mac_address
            # Trigger vendor lookup for newly discovered MAC
            if src_ip not in _resolving:
                _resolving.add(src_ip)
                _executor.submit(_resolve_metadata, src_ip, mac_address)
    
    # Always update counters (fast path)
    NODE_STATS[src_ip]['packets'] += 1
    NODE_STATS[src_ip]['bytes'] += packet_size or 0
    NODE_STATS[src_ip]['last_seen'] = timestamp


def get_active_nodes(limit=50):
    """
    Get all active nodes sorted by traffic (bytes) descending.
    Groups entries by MAC address to deduplicate IPv4/IPv6 pairs.
    
    Args:
        limit: Maximum number of nodes to return
    
    Returns:
        list: List of node dictionaries sorted by bytes (highest first)
    """
    # Step 1: Group by MAC address
    mac_groups = {}  # {mac: [list of node entries]}
    no_mac_nodes = []  # Nodes without MAC addresses
    
    for node in NODE_STATS.values():
        mac = node.get('mac')
        if mac:
            if mac not in mac_groups:
                mac_groups[mac] = []
            mac_groups[mac].append(node)
        else:
            no_mac_nodes.append(node)
    
    # Step 2: Merge entries within each MAC group
    merged_nodes = []
    
    for mac, entries in mac_groups.items():
        if len(entries) == 1:
            # Single entry, no merge needed
            merged_nodes.append(entries[0])
        else:
            # Multiple IPs with same MAC - merge them
            merged = {
                'mac': mac,
                'packets': 0,
                'bytes': 0,
                'hostname': None,
                'vendor': None,
                'first_seen': None,
                'last_seen': None,
                'ip': None,  # Primary IP (prefer IPv4)
                'secondary_ip': None,  # Secondary IP (usually IPv6)
                'all_ips': []
            }
            
            ipv4_ip = None
            ipv6_ip = None
            
            for entry in entries:
                # Sum stats
                merged['packets'] += entry.get('packets', 0)
                merged['bytes'] += entry.get('bytes', 0)
                
                # Track all IPs
                ip = entry.get('ip')
                if ip:
                    merged['all_ips'].append(ip)
                    # Categorize by IP version
                    if ':' in ip:  # IPv6
                        ipv6_ip = ip
                    else:  # IPv4
                        ipv4_ip = ip
                
                # Keep best hostname (non-null takes priority)
                if entry.get('hostname') and not merged['hostname']:
                    merged['hostname'] = entry['hostname']
                
                # Keep best vendor (non-null, non-Resolving takes priority)
                entry_vendor = entry.get('vendor')
                if entry_vendor and entry_vendor not in ('Unknown', 'Resolving...'):
                    if not merged['vendor'] or merged['vendor'] in ('Unknown', 'Resolving...'):
                        merged['vendor'] = entry_vendor
                elif entry_vendor and not merged['vendor']:
                    merged['vendor'] = entry_vendor
                
                # Track first/last seen
                entry_first = entry.get('first_seen')
                entry_last = entry.get('last_seen')
                if entry_first and (not merged['first_seen'] or entry_first < merged['first_seen']):
                    merged['first_seen'] = entry_first
                if entry_last and (not merged['last_seen'] or entry_last > merged['last_seen']):
                    merged['last_seen'] = entry_last
            
            # Set primary IP (prefer IPv4) and secondary
            if ipv4_ip:
                merged['ip'] = ipv4_ip
                merged['secondary_ip'] = ipv6_ip
            elif ipv6_ip:
                merged['ip'] = ipv6_ip
            elif merged['all_ips']:
                merged['ip'] = merged['all_ips'][0]
            
            merged_nodes.append(merged)
    
    # Add nodes without MAC addresses (can't deduplicate these)
    merged_nodes.extend(no_mac_nodes)
    
    # Step 3: Sort by bytes (highest first)
    merged_nodes.sort(key=lambda x: x.get('bytes', 0), reverse=True)
    
    return merged_nodes[:limit]


def get_node_stats(ip):
    """
    Get statistics for a specific IP address.
    
    Args:
        ip: IP address to look up
    
    Returns:
        dict or None: Node stats or None if not found
    """
    return NODE_STATS.get(ip)


def clear_node_stats():
    """Clear all node statistics."""
    global NODE_STATS
    NODE_STATS = {}
    _resolving.clear()
    return True


def get_node_count():
    """Get the total number of unique nodes."""
    return len(NODE_STATS)
