# src/handlers/socket_handlers.py
from datetime import datetime
from flask import request
from flask_login import current_user
from flask_socketio import join_room, leave_room, send

from src.middleware.socket_auth import socket_auth_middleware, socket_rate_limit
from src.utils.input_sanitizer import sanitize_message, sanitize_room_code
from src.services.logger_service import AdvancedLogger
from argon2 import PasswordHasher

# Estructuras globales para el chat
chat_rooms = {}
room_attempts = {}
verified_sessions = {}

# Dependencias a inicializar
logger = None
ph = None

def init_socket_handlers(logger_instance, password_hasher):
    """Inicializar dependencias de los handlers de socket"""
    global logger, ph
    logger = logger_instance
    ph = password_hasher

def register_socket_handlers(socketio):
    """Registrar todos los handlers de SocketIO"""
    
    @socketio.on('connect')
    def handle_connect():
        """✅ Validación de conexión SocketIO"""
        if not current_user.is_authenticated:
            return False  # Rechazar conexión no autenticada
        
        logger.log_chat(
            usuario=current_user.id,
            accion='SOCKET_CONNECT',
            sala='system',
            tamano_mensaje=0
        )
        return True

    @socketio.on('disconnect')
    def handle_disconnect():
        """✅ Logging de desconexión"""
        logger.log_chat(
            usuario=current_user.id if current_user.is_authenticated else 'unknown',
            accion='SOCKET_DISCONNECT',
            sala='system',
            tamano_mensaje=0
        )

    @socketio.on('join')
    @socket_auth_middleware
    @socket_rate_limit(max_per_minute=30)
    def on_join(data):
        """✅ JOIN MEJORADO CON PROTECCIÓN DOS"""
        username = current_user.id
        room_code = sanitize_room_code(data.get('room', 'default'))
        password = data.get('password', '')[:100]  # Limitar longitud
        client_id = request.sid
        
        # ✅ PROTECCIÓN DOS MEJORADA
        from flask_limiter.util import get_remote_address
        attempt_key = f"{get_remote_address()}:{room_code}"
        current_time = datetime.now().timestamp()
        
        # Limitar intentos: 1 cada 3 segundos
        if attempt_key in room_attempts:
            last_attempt = room_attempts[attempt_key]['last_attempt']
            if current_time - last_attempt < 3:
                send({'msg': 'Espere 3 segundos entre intentos.', 'type': 'error'})
                return
        
        # ✅ CACHE DE SESIONES VERIFICADAS
        session_key = f"{client_id}:{room_code}"
        if session_key in verified_sessions:
            if verified_sessions[session_key] == password:
                join_room(room_code)
                send({'msg': f"👋 {username} reconectado.", 'user': 'Servidor'}, to=room_code)
                return
        
        # Verificación con Argon2
        if room_code in chat_rooms:
            try:
                ph.verify(chat_rooms[room_code], password)
                # ✅ GUARDAR EN CACHE
                verified_sessions[session_key] = password
                room_attempts[attempt_key] = {
                    'last_attempt': current_time, 
                    'attempts': 0
                }
            except Exception:
                # ✅ TRACK INTENTOS FALLIDOS
                if attempt_key not in room_attempts:
                    room_attempts[attempt_key] = {
                        'last_attempt': current_time, 
                        'attempts': 1
                    }
                else:
                    room_attempts[attempt_key]['attempts'] += 1
                    room_attempts[attempt_key]['last_attempt'] = current_time
                
                send({'msg': f'Contraseña incorrecta. Intento {room_attempts[attempt_key]["attempts"]}', 
                     'type': 'error'})
                return
        else:
            chat_rooms[room_code] = ph.hash(password)

        join_room(room_code)
        send({'msg': f"👋 {username} se ha unido.", 'user': 'Servidor'}, to=room_code)
        
        logger.log_chat(
            usuario=username,
            accion='JOIN_ROOM',
            sala=room_code,
            tamano_mensaje=0
        )

    @socketio.on('message')
    @socket_auth_middleware
    @socket_rate_limit(max_per_minute=60)  # 1 mensaje por segundo máximo
    def handle_message(data):
        """✅ MANEJO DE MENSAJES CON VALIDACIÓN"""
        username = current_user.id
        room = sanitize_room_code(data.get('room', ''))
        msg = sanitize_message(data.get('msg', ''))
        
        # ✅ VALIDACIÓN CONTRA INYECCIÓN/SCRIPTS
        if not room or not msg.strip():
            return
        
        send({
            'msg': msg, 
            'user': username, 
            'timestamp': datetime.now().isoformat()
        }, to=room)
        
        logger.log_chat(
            usuario=username,
            accion='SEND_MESSAGE',
            sala=room,
            tamano_mensaje=len(msg.encode('utf-8'))
        )

    @socketio.on('leave')
    @socket_auth_middleware
    def on_leave(data):
        """Manejar salida de sala"""
        username = current_user.id
        room = sanitize_room_code(data.get('room', ''))
        
        leave_room(room)
        send({'msg': f"👋 {username} ha salido.", 'user': 'Servidor'}, to=room)
        
        logger.log_chat(
            usuario=username,
            accion='LEAVE_ROOM',
            sala=room,
            tamano_mensaje=0
        )
