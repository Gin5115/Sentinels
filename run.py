"""
Entry point for the Sentinels Network Traffic Analyzer.
Run with: python run.py
"""
import os
from app import create_app, socketio

# Get configuration from environment or use default
config_name = os.environ.get('FLASK_ENV', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    # Run with SocketIO support
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
