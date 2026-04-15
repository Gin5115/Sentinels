"""
SQLite models for storing threat logs.
Provides CRUD operations for the threats database.
"""
import sqlite3
import os
from datetime import datetime


# Database path - relative to project root
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'instance', 'threats.db')


def _get_connection():
    """Get a database connection with row factory enabled."""
    # Ensure instance directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


def init_db():
    """Initialize the database schema."""
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            threat_type TEXT,
            severity TEXT,
            description TEXT,
            packet_size INTEGER,
            payload TEXT,
            detection_method TEXT DEFAULT 'Heuristic'
        );
    ''')
    # Add indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_source_ip ON threats(source_ip)')
    
    conn.commit()
    conn.close()
    print('[Database] Threats table initialized')


def log_threat(source_ip, destination_ip, protocol, threat_type,
               severity='MEDIUM', description=None, packet_size=None,
               payload=None, detection_method='Heuristic'):
    """
    Log a new threat to the database.
    
    Args:
        source_ip: Source IP address
        destination_ip: Destination IP address
        protocol: Protocol (TCP, UDP, ICMP, etc.)
        threat_type: Type of threat detected
        severity: Threat severity (LOW, MEDIUM, HIGH, CRITICAL)
        description: Optional description
        packet_size: Optional packet size in bytes
        payload: Optional packet payload content
    
    Returns:
        int: The ID of the inserted threat
    """
    conn = _get_connection()
    cursor = conn.cursor()
    
    # Check if payload column exists (migration for existing DB)
    # Run migrations for any missing columns on existing DBs
    for col, typedef in [('payload', 'TEXT'), ('detection_method', "TEXT DEFAULT 'Heuristic'")]:
        try:
            cursor.execute(f'ALTER TABLE threats ADD COLUMN {col} {typedef}')
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists

    try:
        cursor.execute('''
            INSERT INTO threats (source_ip, destination_ip, protocol, threat_type,
                                severity, description, packet_size, payload,
                                detection_method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (source_ip, destination_ip, protocol, threat_type,
              severity, description, packet_size, payload, detection_method))
    except Exception as e:
        print(f'[Database] Error logging threat: {e}')
            
    conn.commit()
    threat_id = cursor.lastrowid
    conn.close()
    return threat_id


def get_all_threats(limit=50):
    """
    Get all threats from the database, ordered by most recent first.
    
    Args:
        limit: Maximum number of threats to return (default: 50).
               Set to None to return all records.
    
    Returns:
        list: List of dictionaries containing threat data
    """
    conn = _get_connection()
    cursor = conn.cursor()
    
    if limit is None:
        cursor.execute('SELECT * FROM threats ORDER BY id DESC')
    else:
        cursor.execute('''
            SELECT * FROM threats 
            ORDER BY id DESC 
            LIMIT ?
        ''', (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    # Convert sqlite3.Row objects to dictionaries
    return [dict(row) for row in rows]


def get_threat_by_id(threat_id):
    """
    Get a specific threat by its ID.
    
    Args:
        threat_id: The ID of the threat to retrieve
    
    Returns:
        dict or None: Threat data as dictionary, or None if not found
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM threats WHERE id = ?', (threat_id,))
    row = cursor.fetchone()
    conn.close()
    
    return dict(row) if row else None


def delete_threat(threat_id):
    """
    Delete a specific threat by its ID.
    
    Args:
        threat_id: The ID of the threat to delete
    
    Returns:
        bool: True if a row was deleted, False otherwise
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM threats WHERE id = ?', (threat_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def clear_threat_history():
    """
    Delete all threats from the database.
    Used for the 'Clear All' functionality.
    
    Returns:
        int: Number of rows deleted
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM threats')
    conn.commit()
    count = cursor.rowcount
    conn.close()
    print(f'[Database] Cleared {count} threat records')
    return count


def get_threat_stats():
    """
    Get summary statistics about threats.
    
    Returns:
        dict: Statistics including total count and counts by type
    """
    conn = _get_connection()
    cursor = conn.cursor()
    
    # Total count
    cursor.execute('SELECT COUNT(*) as total FROM threats')
    total = cursor.fetchone()['total']
    
    # Count by threat type
    cursor.execute('''
        SELECT threat_type, COUNT(*) as count 
        FROM threats 
        GROUP BY threat_type 
        ORDER BY count DESC
    ''')
    by_type = {row['threat_type']: row['count'] for row in cursor.fetchall()}
    
    # Count by severity
    cursor.execute('''
        SELECT severity, COUNT(*) as count 
        FROM threats 
        GROUP BY severity
    ''')
    by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
    
    conn.close()
    
    return {
        'total': total,
        'by_type': by_type,
        'by_severity': by_severity
    }


# Legacy class-based interface for backwards compatibility
class ThreatLog:
    """Legacy class-based model for threat log entries."""
    
    def __init__(self, db_path=None):
        if db_path:
            global DB_PATH
            DB_PATH = db_path
    
    def init_db(self):
        return init_db()
    
    def log_threat(self, *args, **kwargs):
        return log_threat(*args, **kwargs)
    
    def get_all_threats(self, limit=50):
        return get_all_threats(limit)
    
    def delete_threat(self, threat_id):
        return delete_threat(threat_id)
    
    def clear_threat_history(self):
        return clear_threat_history()
