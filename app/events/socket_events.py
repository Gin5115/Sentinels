"""
SocketIO event handlers for real-time packet streaming.
Connects the PacketSniffer to Flask-SocketIO for live traffic monitoring.
"""
import os
import threading
import time
from collections import deque
from flask import request
from flask_socketio import emit

import psutil

from app import socketio
from app.sniffer.capture import PacketSniffer
from app.models.nodes import update_node_stats, get_node_count, clear_node_stats
from app.models.threat import clear_threat_history
from app.utils.ip_resolver import get_resolver
from app.utils.stats_manager import traffic_stats
from app.utils.threat_engine import get_threat_engine
from app.utils.flow_tracker import get_flow_tracker

# Global state
_sniffer = None
_connected_clients = set()
_system_monitor_running = False
_top_talkers_monitor_running = False
TOTAL_PACKETS = 0
THREAT_COUNT = 0
MONITORING_ACTIVE = False
PROTOCOL_STATS = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
THREAT_IPS = set()  # IPs that have triggered at least one threat alert

# Lightweight metadata ring buffer (50K entries, no payload)
PACKET_BUFFER = deque(maxlen=50000)
# Full-detail buffer for on-demand packet inspection (payload included)
PACKET_DETAIL_BUFFER = deque(maxlen=1000)


def _get_size(bytes_val):
    """Convert bytes to human-readable format (KB, MB, GB)."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"


def get_system_stats():
    """
    Get current system resource usage for this process.
    Returns detailed CPU, RAM, Disk, and DB size stats.
    Includes both Script-specific and System-wide metrics.
    """
    try:
        process = psutil.Process(os.getpid())
        
        # CPU
        cpu_script = process.cpu_percent(interval=None)
        cpu_system = psutil.cpu_percent(interval=None)
        
        # RAM
        # Script specific
        ram_script_used = process.memory_info().rss
        # System wide
        mem_info = psutil.virtual_memory()
        ram_system_used = mem_info.used
        ram_system_total = mem_info.total
        ram_system_percent = mem_info.percent
        
        # Disk (System Capacity)
        disk_usage = psutil.disk_usage('.')
        
        # Database file size
        # Check both potential locations
        db_path = os.path.join(os.getcwd(), 'instance', 'threats.db')
        if not os.path.exists(db_path):
             db_path = os.path.join(os.getcwd(), 'sentinels.db')
             
        if os.path.exists(db_path):
            db_size = os.path.getsize(db_path)
        else:
            db_size = 0
        
        return {
            'cpu_script': round(cpu_script, 1),
            'cpu_system': round(cpu_system, 1),
            
            'ram_script_used': _get_size(ram_script_used),
            'ram_system_used': _get_size(ram_system_used),
            'ram_system_total': _get_size(ram_system_total),
            'ram_system_percent': round(ram_system_percent, 1),
            
            'disk_system_used': _get_size(disk_usage.used),
            'disk_system_total': _get_size(disk_usage.total),
            'disk_system_percent': round(disk_usage.percent, 1),
            
            'db_size': _get_size(db_size)
        }
    except Exception as e:
        print(f'[Sentinels] Error getting system stats: {e}')
        return {
            'cpu_script': 0, 'cpu_system': 0,
            'ram_script_used': '0 B', 'ram_system_used': '0 B', 'ram_system_total': '0 B', 'ram_system_percent': 0,
            'disk_system_used': '0 B', 'disk_system_total': '0 B', 'disk_system_percent': 0,
            'db_size': '0 B'
        }


def _system_monitor_thread():
    """
    Background thread that periodically emits system usage stats.
    Runs every 2 seconds.
    """
    global _system_monitor_running
    _system_monitor_running = True
    
    print('[Sentinels] System monitor thread started')
    
    while _system_monitor_running and len(_connected_clients) > 0:
        stats = get_system_stats()
        socketio.emit('system_usage', stats, namespace='/')
        time.sleep(2)
    
    _system_monitor_running = False
    print('[Sentinels] System monitor thread stopped')


def start_system_monitor():
    """Start the system monitoring background thread if not already running."""
    global _system_monitor_running
    
    if not _system_monitor_running and len(_connected_clients) > 0:
        thread = threading.Thread(target=_system_monitor_thread, daemon=True)
        thread.start()


# ===== Top Talkers Background Monitor =====
def _top_talkers_monitor_thread():
    """Background thread that emits top talkers data every 2 seconds."""
    global _top_talkers_monitor_running
    _top_talkers_monitor_running = True
    print('[Sentinels] Top Talkers monitor thread started')
    
    while _top_talkers_monitor_running and len(_connected_clients) > 0:
        try:
            top_talkers = traffic_stats.get_top(5)
            socketio.emit('update_top_talkers', top_talkers, namespace='/')
        except Exception as e:
            print(f'[Sentinels] Top talkers emit error: {e}')
        time.sleep(2)
    
    _top_talkers_monitor_running = False
    print('[Sentinels] Top Talkers monitor thread stopped')


def start_top_talkers_monitor():
    """Start the top talkers monitoring thread if not already running."""
    global _top_talkers_monitor_running
    
    if not _top_talkers_monitor_running and len(_connected_clients) > 0:
        thread = threading.Thread(target=_top_talkers_monitor_thread, daemon=True)
        thread.start()


def emit_packet(packet_data):
    """
    Callback function for the PacketSniffer.
    Emits packet data to all connected clients via SocketIO.
    Uses socketio.emit with namespace to work across threads.

    Args:
        packet_data: Dictionary containing packet information
    """
    global TOTAL_PACKETS, THREAT_COUNT, PROTOCOL_STATS, THREAT_IPS
    TOTAL_PACKETS += 1
    
    # Track protocol distribution
    protocol = packet_data.get('protocol', 'Other')
    if protocol in PROTOCOL_STATS:
        PROTOCOL_STATS[protocol] += 1
    else:
        PROTOCOL_STATS['Other'] += 1
    
    # Update node statistics with MAC address for fingerprinting
    update_node_stats(
        packet_data.get('src_ip'), 
        packet_data.get('len'),
        mac_address=packet_data.get('mac_src')
    )
    
    # Add unique ID for on-demand lookup
    packet_data['id'] = TOTAL_PACKETS

    # Full packet (with payload) goes into small detail buffer only
    PACKET_DETAIL_BUFFER.append(packet_data)

    # Lightweight metadata (no payload) goes into the large ring buffer
    lightweight_packet = {
        'id': packet_data['id'],
        'timestamp': packet_data.get('timestamp'),
        'src_ip': packet_data.get('src_ip'),
        'dst_ip': packet_data.get('dst_ip'),
        'protocol': packet_data.get('protocol'),
        'len': packet_data.get('len'),
        'is_threat': packet_data.get('is_threat', False),
        'threat_type': packet_data.get('threat_type'),
        'src_port': packet_data.get('src_port'),
        'dst_port': packet_data.get('dst_port'),
    }
    PACKET_BUFFER.append(lightweight_packet)

    # Emit only lightweight data to all clients
    socketio.emit('new_packet', lightweight_packet, namespace='/')
    
    # Emit heuristic threat alerts (from ThreatEngine)
    if packet_data.get('heuristic_threat'):
        threat = packet_data['heuristic_threat']
        THREAT_COUNT += 1
        src = packet_data.get('src_ip')
        if src:
            THREAT_IPS.add(src)
        socketio.emit('threat_alert', threat, namespace='/')

    # Emit ML threat alerts (from RandomForest flow classifier)
    for ml_threat in packet_data.get('ml_threats', []):
        THREAT_COUNT += 1
        src = ml_threat.get('ip')
        if src:
            THREAT_IPS.add(src)
        socketio.emit('threat_alert', ml_threat, namespace='/')


def get_sniffer():
    """Get or create the global sniffer instance."""
    global _sniffer
    if _sniffer is None:
        _sniffer = PacketSniffer(callback_func=emit_packet)
    return _sniffer


@socketio.on('connect')
def handle_connect():
    """
    Handle client connection.
    Only starts sniffer if MONITORING_ACTIVE is True.
    """
    global MONITORING_ACTIVE
    
    client_id = request.sid
    _connected_clients.add(client_id)
    
    print(f'[Sentinels] Client connected: {client_id}')
    print(f'[Sentinels] Total clients: {len(_connected_clients)}')
    
    sniffer = get_sniffer()
    
    # Only auto-start if monitoring is active
    if MONITORING_ACTIVE and not sniffer.is_running():
        try:
            print('[Sentinels] Starting packet sniffer...')
            interfaces = PacketSniffer.get_available_interfaces()
            print(f'[Sentinels] Available interfaces: {len(interfaces)}')
            for iface in interfaces[:5]:
                print(f'  - {iface.get("name")}: {iface.get("description", "")[:50]}')
            
            success = sniffer.start()
            if success:
                print('[Sentinels] ✓ Packet sniffer started successfully!')
            else:
                print('[Sentinels] ✗ Failed to start sniffer')
        except Exception as e:
            print(f'[Sentinels] ✗ ERROR starting sniffer: {e}')
            emit('error', {'message': f'Sniffer error: {str(e)}'})
    
    # Sync in-memory threat count with actual DB count (prevents drift
    # when Clear History is used without a full session restart)
    from app.models.threat import get_threat_stats
    global THREAT_COUNT
    THREAT_COUNT = get_threat_stats().get('total', THREAT_COUNT)

    # Send initial stats to the newly connected client
    emit('init_stats', {
        'total_packets': TOTAL_PACKETS,
        'active_ips': get_node_count(),
        'threat_count': THREAT_COUNT,
        'monitoring_active': MONITORING_ACTIVE,
        'protocol_stats': PROTOCOL_STATS
    })
    
    emit('status', {
        'message': 'Connected to Sentinels Traffic Analyzer',
        'sniffer_active': sniffer.is_running()
    })
    
    # Start system resource monitor if not already running
    start_system_monitor()
    
    # Start top talkers monitor
    start_top_talkers_monitor()


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    client_id = request.sid
    _connected_clients.discard(client_id)
    
    print(f'Client disconnected: {client_id}')
    print(f'Remaining clients: {len(_connected_clients)}')


@socketio.on('get_all_connections')
def handle_get_all_connections():
    """
    Return all IP connections for the Connection Inspector.
    Enriches with cached geo data (no API calls = rate limit safe).
    """
    try:
        all_connections = traffic_stats.get_all()
        resolver = get_resolver()
        
        # Enrich each connection with cached geo data and threat status
        for conn in all_connections:
            ip = conn.get('ip')
            cached_geo = resolver.get_cached_geo(ip)

            if cached_geo:
                conn['geo'] = cached_geo
            else:
                if resolver.is_private(ip):
                    conn['geo'] = {'flag': '💻', 'country': 'LAN', 'city': 'Local Network', 'lat': None, 'lon': None}
                else:
                    conn['geo'] = {'flag': '🌐', 'country': 'Unknown', 'city': 'Unknown', 'lat': None, 'lon': None}

            conn['is_threat'] = ip in THREAT_IPS
        
        emit('all_connections_data', all_connections)
    except Exception as e:
        print(f'[Sentinels] Error getting all connections: {e}')
        emit('all_connections_data', [])


@socketio.on('resolve_ip')
def handle_resolve_ip(data):
    """
    Resolve an IP address to a human-readable name.
    Uses async resolution to avoid blocking.
    
    Args:
        data: dict with 'ip' key or just the IP string
    """
    ip = data.get('ip') if isinstance(data, dict) else data
    
    if not ip:
        return
    
    client_id = request.sid
    resolver = get_resolver()
    
    # Check cache first (instant response)
    cached_name = resolver.get_cached(ip)
    if cached_name is not None:
        emit('ip_resolved', {'ip': ip, 'name': cached_name})
        return
    
    # Async resolution (non-blocking)
    def on_resolved(result):
        socketio.emit('ip_resolved', result, room=client_id)
    
    resolver.resolve_async(ip, on_resolved)


@socketio.on('resolve_geo')
def handle_resolve_geo(data):
    """
    Resolve geo-location for an IP address.
    Returns country, city, and flag.
    """
    ip = data.get('ip') if isinstance(data, dict) else data
    
    if not ip:
        return
    
    client_id = request.sid
    resolver = get_resolver()
    
    # Async geo resolution
    def on_geo_resolved(result):
        socketio.emit('geo_resolved', result, room=client_id)
    
    resolver.resolve_geo_async(ip, on_geo_resolved)


@socketio.on('toggle_monitoring')
def handle_toggle_monitoring(data):
    """
    Toggle monitoring state globally.
    
    Args:
        data: dict with 'target_state' boolean
    """
    global MONITORING_ACTIVE
    
    target_state = data.get('target_state', False) if isinstance(data, dict) else bool(data)
    MONITORING_ACTIVE = target_state
    
    sniffer = get_sniffer()
    
    if MONITORING_ACTIVE:
        if not sniffer.is_running():
            success = sniffer.start()
            print(f'[Sentinels] Monitoring STARTED (success: {success})')
    else:
        if sniffer.is_running():
            sniffer.stop()
            print('[Sentinels] Monitoring STOPPED')
    
    # Broadcast to all clients
    socketio.emit('monitoring_status', {
        'active': MONITORING_ACTIVE,
        'sniffer_running': sniffer.is_running()
    }, namespace='/')


@socketio.on('restart_session')
def handle_restart_session():
    """
    Restart the monitoring session.
    Stops sniffer, clears all data, resets counters.
    """
    global MONITORING_ACTIVE, TOTAL_PACKETS, THREAT_COUNT, PROTOCOL_STATS
    
    print('[Sentinels] Session restart requested')
    
    # Stop sniffer
    sniffer = get_sniffer()
    if sniffer.is_running():
        sniffer.stop()
    
    # Reset state
    MONITORING_ACTIVE = False
    TOTAL_PACKETS = 0
    THREAT_COUNT = 0
    PROTOCOL_STATS = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
    THREAT_IPS.clear()
    
    # Clear stored data
    clear_node_stats()
    clear_threat_history()
    PACKET_BUFFER.clear()
    PACKET_DETAIL_BUFFER.clear()
    traffic_stats.clear()
    get_threat_engine().clear()
    get_flow_tracker().clear()
    get_resolver().clear_cache()

    print('[Sentinels] Session data cleared')
    
    # Broadcast to all clients
    socketio.emit('session_restarted', {
        'message': 'Session has been reset',
        'total_packets': 0,
        'active_ips': 0,
        'threat_count': 0,
        'monitoring_active': False,
        'protocol_stats': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
    }, namespace='/')


@socketio.on('start_capture')
def handle_start_capture(data=None):
    """Manually start packet capture."""
    global MONITORING_ACTIVE
    
    interface = data.get('interface') if data else None
    sniffer = get_sniffer()
    
    if sniffer.is_running():
        emit('capture_status', {'status': 'already_running'})
        return
    
    success = sniffer.start(interface=interface)
    MONITORING_ACTIVE = success
    
    emit('capture_status', {
        'status': 'started' if success else 'failed',
        'interface': interface or 'default'
    })
    
    # Broadcast status change
    socketio.emit('monitoring_status', {
        'active': MONITORING_ACTIVE,
        'sniffer_running': sniffer.is_running()
    }, namespace='/')


@socketio.on('stop_capture')
def handle_stop_capture():
    """Manually stop packet capture."""
    global MONITORING_ACTIVE
    
    sniffer = get_sniffer()
    
    if not sniffer.is_running():
        emit('capture_status', {'status': 'not_running'})
        return
    
    sniffer.stop()
    MONITORING_ACTIVE = False
    
    emit('capture_status', {'status': 'stopped'})
    
    # Broadcast status change
    socketio.emit('monitoring_status', {
        'active': MONITORING_ACTIVE,
        'sniffer_running': False
    }, namespace='/')


@socketio.on('get_interfaces')
def handle_get_interfaces():
    """Send list of available network interfaces to the client."""
    interfaces = PacketSniffer.get_available_interfaces()
    emit('interfaces_list', {'interfaces': interfaces})


@socketio.on('get_status')
def handle_get_status():
    """Send current sniffer status to the client."""
    sniffer = get_sniffer()
    emit('status', {
        'sniffer_active': sniffer.is_running(),
        'monitoring_active': MONITORING_ACTIVE,
        'connected_clients': len(_connected_clients)
    })
