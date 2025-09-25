# src/middleware/socket_auth.py
from flask import request
from flask_login import current_user
from functools import wraps

def socket_auth_middleware(f):
    """Middleware de autenticación para eventos SocketIO"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            # Rechazar evento si el usuario no está autenticado
            return {'error': 'Unauthorized'}, 401
        
        # Verificar que el usuario tenga permisos básicos
        if not hasattr(current_user, 'id') or not current_user.id:
            return {'error': 'Invalid user session'}, 401
            
        return f(*args, **kwargs)
    return decorated_function

def socket_rate_limit(max_per_minute: int = 60):
    """Middleware de rate limiting para SocketIO"""
    from collections import defaultdict
    from datetime import datetime, timedelta
    import time
    
    request_counts = defaultdict(list)
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_id = request.sid
            now = time.time()
            
            # Limpiar registros antiguos (más de 1 minuto)
            request_counts[client_id] = [
                timestamp for timestamp in request_counts[client_id] 
                if now - timestamp < 60
            ]
            
            # Verificar límite
            if len(request_counts[client_id]) >= max_per_minute:
                return {'error': 'Rate limit exceeded'}, 429
            
            # Registrar nuevo evento
            request_counts[client_id].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
