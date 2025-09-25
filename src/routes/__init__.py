# src/routes/__init__.py
from .auth_routes import auth_bp
from .file_routes import file_bp
from .chat_routes import chat_bp

__all__ = ['auth_bp', 'file_bp', 'chat_bp']
