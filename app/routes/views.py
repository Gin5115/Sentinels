"""
Flask routes for the Sentinels Network Traffic Analyzer.
"""
import csv
import io
import os
import sys
from flask import render_template, jsonify, request, Response
from app.routes import main_bp
from app.models.threat import get_all_threats, delete_threat, clear_threat_history
from app.models.nodes import get_active_nodes
from app.events.socket_events import PACKET_BUFFER, PACKET_DETAIL_BUFFER


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


@main_bp.route('/geo')
def geo():
    """Geo-IP world map page."""
    return render_template('geo.html')


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
    # Reset the in-memory counter so dashboard stays in sync
    from app.events.socket_events import socketio
    import app.events.socket_events as _se
    _se.THREAT_COUNT = 0
    socketio.emit('threat_count_reset', {'threat_count': 0}, namespace='/')
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


@main_bp.route('/api/nodes')
def api_get_nodes():
    """API endpoint to get active nodes as JSON."""
    nodes = get_active_nodes(limit=100)
    return jsonify({'success': True, 'nodes': nodes})


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
    # Search detail buffer (last 1000 full packets) for matching ID
    for packet in PACKET_DETAIL_BUFFER:
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


@main_bp.route('/api/ml/status')
def api_ml_status():
    """Return ML engine status (model loaded, classes, etc.)."""
    from app.utils.ml_engine import get_ml_engine
    status = get_ml_engine().get_status()
    return jsonify({'success': True, 'ml': status})



@main_bp.route('/api/ml/reload', methods=['POST'])
def api_ml_reload():
    """Reload the model from the default path on disk."""
    from app.utils.ml_engine import get_ml_engine
    engine = get_ml_engine()
    ok = engine.load_model()   # reloads from default path
    if ok:
        return jsonify({'success': True, 'ml': engine.get_status()})
    return jsonify({'success': False, 'error': f'Model file not found at {engine._model_path}'}), 404


@main_bp.route('/api/ml/remove', methods=['POST'])
def api_ml_remove():
    """Delete the installed model file and disable ML detection."""
    dest = os.path.normpath(_ML_MODEL_PATH)
    if os.path.exists(dest):
        os.remove(dest)

    # Reset singleton state without unloading (keep object alive)
    from app.utils import ml_engine as _me
    if _me._ml_engine_instance:
        inst = _me._ml_engine_instance
        inst._model = None
        inst._label_encoder = None
        inst._features = None
        inst._loaded = False
        inst._classes = []

    return jsonify({'success': True, 'message': 'Model removed'})


@main_bp.route('/api/debug/ml')
def api_debug_ml():
    """
    Diagnostic endpoint — shows ML engine state and runs a dummy prediction
    so you can confirm the model is loaded and responding.
    """
    from app.utils.ml_engine import get_ml_engine
    from app.utils.flow_tracker import get_flow_tracker
    from app.utils.detection_config import get_detection_mode
    import numpy as np

    engine = get_ml_engine()
    status = engine.get_status()
    tracker = get_flow_tracker()

    result = {
        'model_loaded': status['loaded'],
        'model_path': status['model_path'],
        'classes': status['classes'],
        'detection_mode': get_detection_mode(),
        'active_flows': len(tracker._flows),
    }

    # Run a dummy prediction if model is loaded
    if status['loaded']:
        try:
            # Craft a feature vector that looks like a DoS flow
            dummy = {f: 0.0 for f in engine._features}
            dummy['Total Fwd Packets']       = 300.0
            dummy['Flow Packets/s']          = 5000.0
            dummy['Flow Bytes/s']            = 200000.0
            dummy['SYN Flag Count']          = 1.0
            dummy['RST Flag Count']          = 1.0
            dummy['Average Packet Size']     = 400.0

            vec = np.array([[dummy.get(f, 0.0) for f in engine._features]], dtype=float)
            vec = np.nan_to_num(vec, nan=0.0, posinf=1e9, neginf=0.0)
            idx   = engine._model.predict(vec)[0]
            label = engine._label_encoder.inverse_transform([idx])[0]
            proba = float(engine._model.predict_proba(vec)[0].max())

            result['test_prediction'] = {
                'label': label,
                'confidence': round(proba * 100, 1),
                'status': 'ok'
            }
        except Exception as exc:
            result['test_prediction'] = {'status': 'error', 'error': str(exc)}

    return jsonify({'success': True, 'debug': result})


@main_bp.route('/api/settings/detection', methods=['GET'])
def api_get_detection_mode():
    """Return the current detection mode."""
    from app.utils.detection_config import get_detection_mode
    return jsonify({'success': True, 'mode': get_detection_mode()})


@main_bp.route('/api/settings/detection', methods=['POST'])
def api_set_detection_mode():
    """Set the detection mode: 'heuristic', 'ml', or 'both'."""
    from app.utils.detection_config import set_detection_mode
    mode = (request.get_json(silent=True) or {}).get('mode', '')
    if set_detection_mode(mode):
        return jsonify({'success': True, 'mode': mode})
    return jsonify({'success': False, 'error': f'Invalid mode "{mode}". Use heuristic, ml, or both.'}), 400


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
