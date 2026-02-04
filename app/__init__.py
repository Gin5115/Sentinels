from flask import Flask
from flask_socketio import SocketIO
from config import config

# Initialize SocketIO without app (will be initialized later)
# Using 'threading' mode for compatibility with Scapy's background threads
socketio = SocketIO()


def create_app(config_name='default'):
    """Application factory pattern."""
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions - use 'threading' mode for Scapy compatibility
    socketio.init_app(app, async_mode='threading', cors_allowed_origins='*')
    
    # Initialize database
    from app.models.threat import init_db
    with app.app_context():
        init_db()
    
    # Register blueprints
    from app.routes import main_bp
    app.register_blueprint(main_bp)
    
    # Import socket events to register handlers
    from app.events import socket_events  # noqa: F401
    
    return app
