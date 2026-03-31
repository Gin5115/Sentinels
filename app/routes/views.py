"""
Flask routes for the Sentinels Network Traffic Analyzer.
"""
import csv
import io
import sys
from flask import render_template, jsonify, request, Response
from app.routes import main_bp
from app.models.threat import get_all_threats, delete_threat, clear_threat_history
from app.models.nodes import get_active_nodes
from app.events.socket_events import PACKET_BUFFER


@main_bp.route('/')
def index():
    """Home page - Dashboard for network traffic analysis."""
    return render_template('index.html')


@main_bp.route('/logs')
def logs():
    """View threat logs page."""
    threats = get_all_threats(limit=200)
    return render_template('logs.html', threats=threats)


@main_bp.route('/nodes')
def nodes():
    """View active network nodes page."""
    nodes = get_active_nodes(limit=100)
    return render_template('nodes.html', nodes=nodes)


@main_bp.route('/feed')
def feed():
    """View live packet feed page."""
    return render_template('feed.html')


@main_bp.route('/settings')
def settings():
    """Settings and data management page."""
    if sys.platform == 'win32':
        platform_name = 'Windows (Npcap)'
    elif sys.platform == 'linux':
        platform_name = 'Linux (libpcap)'
    elif sys.platform == 'darwin':
        platform_name = 'macOS (libpcap)'
    else:
        platform_name = sys.platform
    return render_template('settings.html', platform=platform_name)


# ============ API Routes ============

@main_bp.route('/api/threats', methods=['GET'])
def api_get_threats():
    """API endpoint to get all threats as JSON."""
    limit = request.args.get('limit', 50, type=int)
    threats = get_all_threats(limit=limit)
    return jsonify({'success': True, 'threats': threats})


@main_bp.route('/api/threats/delete/<int:threat_id>', methods=['POST'])
def api_delete_threat(threat_id):
    """API endpoint to delete a specific threat."""
    deleted = delete_threat(threat_id)
    return jsonify({'success': deleted})


@main_bp.route('/api/threats/clear', methods=['POST'])
def api_clear_threats():
    """API endpoint to clear all threat history."""
    count = clear_threat_history()
    return jsonify({'success': True, 'deleted_count': count})


@main_bp.route('/api/threats/export')
def api_export_threats():
    """
    Export all threats as a downloadable CSV file.
    """
    # Get all threats (no limit)
    threats = get_all_threats(limit=None)
    
    # Create in-memory CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    headers = ['ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 
               'Threat Type', 'Severity', 'Description', 'Packet Size']
    writer.writerow(headers)
    
    # Write data rows
    for threat in threats:
        writer.writerow([
            threat.get('id', ''),
            threat.get('timestamp', ''),
            threat.get('source_ip', ''),
            threat.get('destination_ip', ''),
            threat.get('protocol', ''),
            threat.get('threat_type', ''),
            threat.get('severity', ''),
            threat.get('description', ''),
            threat.get('packet_size', '')
        ])
    
    # Create response
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': 'attachment; filename=threat_report.csv',
            'Content-Type': 'text/csv; charset=utf-8'
        }
    )


@main_bp.route('/api/packets')
def api_get_packets():
    """
    API endpoint to get LIGHTWEIGHT packet metadata from the circular buffer.
    Does NOT include payload to prevent memory bloat.
    
    Query params:
        offset: Starting index (default: 0, from newest)
        limit: Number of packets to return (default: 100, max: 50000)
        ip: Optional IP address to filter by (Source OR Destination)
    """
    offset = request.args.get('offset', 0, type=int)
    limit = min(request.args.get('limit', 100, type=int), 50000)
    target_ip = request.args.get('ip')  # Optional filter
    
    # Convert deque to list for slicing (newest first)
    # Note: Creating a list from a large deque is O(N) but typically fast in RAM
    all_packets = list(PACKET_BUFFER)
    all_packets.reverse()  # Newest first
    
    # Filter by IP if requested (Server-side optimization)
    if target_ip:
        filtered_packets = [p for p in all_packets 
                           if p.get('src_ip') == target_ip or p.get('dst_ip') == target_ip]
        total = len(filtered_packets)
        paginated = filtered_packets[offset:offset + limit]
    else:
        total = len(all_packets)
        paginated = all_packets[offset:offset + limit]
    
    # Return LIGHTWEIGHT metadata only (no payload)
    lightweight_packets = [{
        'id': p.get('id'),
        'timestamp': p.get('timestamp'),
        'src_ip': p.get('src_ip'),
        'dst_ip': p.get('dst_ip'),
        'protocol': p.get('protocol'),
        'len': p.get('len'),
        'is_threat': p.get('is_threat', False),
        'threat_type': p.get('threat_type')
    } for p in paginated]
    
    return jsonify({
        'success': True,
        'total': total,
        'offset': offset,
        'limit': limit,
        'packets': lightweight_packets
    })


@main_bp.route('/api/packet/<int:packet_id>')
def api_get_packet_details(packet_id):
    """
    API endpoint to get FULL packet details including payload.
    Used when user clicks a row to view details (on-demand fetch).
    """
    # Search buffer for packet with matching ID
    for packet in PACKET_BUFFER:
        if packet.get('id') == packet_id:
            return jsonify({
                'success': True,
                'packet': packet
            })
    
    return jsonify({
        'success': False,
        'error': 'Packet not found'
    }), 404


@main_bp.route('/api/geo/<ip>')
def api_resolve_geo(ip):
    """
    API endpoint to resolve geo-location for an IP.
    """
    from app.utils.ip_resolver import get_resolver
    resolver = get_resolver()
    geo = resolver.resolve_geo(ip)
    
    return jsonify({
        'success': True,
        'geo': geo
    })


@main_bp.route('/api/threat/<int:threat_id>')
def api_get_threat_details(threat_id):
    """
    API endpoint to get FULL threat details including payload.
    Used for the Threat Logs 'Packet Details' action.
    """
    from app.models.threat import get_threat_by_id
    threat = get_threat_by_id(threat_id)
    
    if threat:
        return jsonify({
            'success': True,
            'threat': threat
        })
    
    return jsonify({
        'success': False,
        'error': 'Threat not found'
    }), 404
