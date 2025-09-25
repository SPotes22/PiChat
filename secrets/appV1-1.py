'''
PiChat - Chat Corporativo Almacenamiento-Básico en Red
Copyright (C) 2025 Santiago Potes Giraldo
SPDX-License-Identifier: GPL-3.0-or-later
'''
import os
import json
from datetime import datetime
from argon2 import PasswordHasher
from src.services.logger_service import AdvancedLogger
from flask import (
    Flask, request, jsonify, redirect, url_for,
    send_from_directory, render_template
)
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_argon2 import Argon2

# --- CONFIGURACIÓN INICIAL MEJORADA ---
UPLOAD_FOLDER='./cuarentena'
app = Flask(__name__)

# ✅ CORS CONFIGURADO SEGURO
CORS(app, origins=[
    "http://localhost:3000",  # Desarrollo frontend
    "https://tudominio.com",  # Producción
    os.getenv("ALLOWED_ORIGINS", "http://localhost:8080")  # Variable entorno
], supports_credentials=True)

# ✅ RATE LIMITING MEJORADO
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="moving-window"  # Más preciso que fixed-window
)

socketio = SocketIO(app, 
    cors_allowed_origins="*",  # ✅ SocketIO necesita su propia config CORS
    async_mode='threading',
    logger=True,
    engineio_logger=False
)

app.secret_key = os.environ.get("SECRET_KEY", "a-very-secret-key-for-dev")
argon2 = Argon2(app)
ph = PasswordHasher()

# ✅ LOGGER MEJORADO PARA CONCURRENCIA
logger = AdvancedLogger(
    logs_dir='./logs',
    max_file_size_mb=10,
    buffer_size=100  # ✅ NUEVO: Buffer para mensajes de chat
)

SERVERFILE = 'server_hist.csv'

# --- CONFIGURACIÓN SEGURIDAD ADICIONAL ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # Solo HTTPS en producción
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # Límite 16MB uploads
    UPLOAD_FOLDER='./cuarentena'
)

print("Configuración de seguridad inicial completada ...")

# --- CARPETA UPLOADS ---
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- USUARIOS BASE CON HARDENING ---
users = {
    os.getenv("ADMIN_USER", "admin"): {
        "password": ph.hash(os.getenv("ADMIN_PASS", "admin123")),
        "role": "administrator",
        "failed_attempts": 0,
        "last_attempt": None
    },
    os.getenv("CLIENT_USER", "cliente"): {
        "password": ph.hash(os.getenv("CLIENT_PASS", "cliente123")),
        "role": "cliente",
        "failed_attempts": 0,
        "last_attempt": None
    },
    os.getenv("USR_USER", "usuario"): {
        "password": ph.hash(os.getenv("USR_PASS", "usuario123")),
        "role": "usuario",
        "failed_attempts": 0,
        "last_attempt": None
    }
}

# ✅ DICCIONARIO PARA PROTECCIÓN DE SALAS
chat_rooms = {}
room_attempts = {}  # Track intentos por sala/IP
verified_sessions = {}  # Cache de sesiones validadas

print("Sistema de autenticación hardening inicializado...")

# --- LOGIN MANAGER MEJORADO ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"  # ✅ Protección adicional

class Usuario(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.rol = role

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return Usuario(user_id, users[user_id]['role'])
    return None

# ✅ FUNCIÓN DE PROTECCIÓN CONTRA FUERZA BRUTA
def check_brute_force_protection(username, max_attempts=5, lockout_time=900):
    """Protección contra fuerza bruta mejorada"""
    now = datetime.now()
    user_data = users.get(username)
    
    if not user_data:
        return False  # Usuario no existe
    
    if user_data['failed_attempts'] >= max_attempts:
        if user_data['last_attempt']:
            time_diff = (now - user_data['last_attempt']).total_seconds()
            if time_diff < lockout_time:  # 15 minutos de bloqueo
                return True  # Está bloqueado
            else:
                # Resetear después del tiempo de bloqueo
                user_data['failed_attempts'] = 0
                user_data['last_attempt'] = None
    return False

# --- RUTAS MEJORADAS ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", deduct_when=lambda response: response.status_code != 200)
def login():
    if current_user.is_authenticated:
        logger.log_archivo(
            usuario=current_user.id,
            accion='LOGIN_REDIRECT_ALREADY_AUTH',
            nombre_archivo=SERVERFILE,
            tamano=0
        )
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        user = request.form['usuario']
        password = request.form['clave']
        
        # ✅ PROTECCIÓN FUERZA BRUTA
        if check_brute_force_protection(user):
            logger.log_archivo(
                usuario=user,
                accion='LOGIN_BLOCKED_BRUTE_FORCE',
                nombre_archivo=SERVERFILE,
                tamano=-1
            )
            return render_template("login.html", 
                                error="Demasiados intentos fallidos. Espere 15 minutos.")
        
        if user in users:
            try:
                ph.verify(users[user]['password'], password)
                # ✅ RESETEO DE INTENTOS AL ÉXITO
                users[user]['failed_attempts'] = 0
                users[user]['last_attempt'] = None
                
                login_user(Usuario(user, users[user]['role']))
                
                logger.log_archivo(
                    usuario=user,
                    accion='LOGIN_EXITOSO',
                    nombre_archivo=SERVERFILE,
                    tamano=0
                )
                return redirect(url_for('inicio'))
            except Exception as e:
                # ✅ INCREMENTO DE INTENTOS FALLIDOS
                users[user]['failed_attempts'] += 1
                users[user]['last_attempt'] = datetime.now()
                
                logger.log_archivo(
                    usuario=user,
                    accion=f'LOGIN_FALLIDO_ATTEMPT_{users[user]["failed_attempts"]}',
                    nombre_archivo=SERVERFILE,
                    tamano=-1
                )
        else:
            logger.log_archivo(
                usuario=user,
                accion='LOGIN_USUARIO_NO_EXISTE',
                nombre_archivo=SERVERFILE,
                tamano=-1
            )
            
        return render_template("login.html", error="Credenciales inválidas.")
    return render_template("login.html")

# ... (resto de rutas similares con mejoras de logging)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    # ✅ CORREGIDO: Logging antes de logout
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER LOG OUT - EXITED SESSION - SUCCESS',
        nombre_archivo='user_hist.csv',
        tamano=0
    )
    logout_user()
    return redirect(url_for('login'))

@app.route('/inicio')
@login_required
def inicio():
    # ✅ CORREGIDO: Logging de acceso a inicio
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER ACCESS INICIO - SERVER MSG - SUCCESS',
        nombre_archivo='user_hist.csv',
        tamano=0
    )
    return render_template('inicio.html', current_user=current_user)

# --- FUNCIONALIDAD DE ARCHIVOS ---
@app.route('/subir', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute")  # ✅ NUEVO: Rate limiting para subida
def subir():
    if current_user.rol == 'usuario':
        return 'No tienes permiso para subir archivos', 403
    if request.method == 'POST':
        if 'archivo' not in request.files:
            return 'No se encontró el archivo', 400
        archivo = request.files['archivo']
        if archivo.filename == '':
            return 'No se seleccionó ningún archivo', 400
        filename = secure_filename(archivo.filename)
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # ✅ CORREGIDO: Logging de archivo subido
        logger.log_archivo(
            usuario=current_user.id,
            accion='subir',
            nombre_archivo=filename,
            tamano=archivo.content_length
        )
        return redirect(url_for('listar'))
    return render_template("subir.html")

@app.route('/listar')
@login_required
def listar():
    archivos = os.listdir(UPLOAD_FOLDER)

    # ✅ CORREGIDO: Logging de listado de archivos
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER LISTS FILES FROM SERVER - SUCCESS',
        nombre_archivo='file_list',
        tamano=len(archivos)
    )
    return render_template("listar.html", archivos=archivos)

@app.route('/descargar/<nombre>')
@login_required
@limiter.limit("10 per minute")  # ✅ NUEVO: Rate limiting para descargas
def descargar(nombre):
    # ✅ CORREGIDO: Logging de descarga
    file_path = os.path.join(UPLOAD_FOLDER, nombre)
    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    logger.log_archivo(
        usuario=current_user.id,
        accion='USER DOWNLOADS FILE - SUCCESS',
        nombre_archivo=nombre,
        tamano=file_size
    )
    return send_from_directory(UPLOAD_FOLDER, nombre, as_attachment=True)

@app.route('/eliminar/<nombre>')
@login_required
@limiter.limit("3 per minute")  # ✅ NUEVO: Rate limiting estricto para eliminación
def eliminar(nombre):
    if current_user.rol != 'administrator':
        return 'No tienes permiso para eliminar archivos', 403
    try:
        file_path = os.path.join(UPLOAD_FOLDER, secure_filename(nombre))
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else -1
        os.remove(file_path)

        # ✅ CORREGIDO: Logging de eliminación
        logger.log_archivo(
            usuario=current_user.id,
            accion='ARCHIVO ELIMINADO - SUCCESS',
            nombre_archivo=nombre,
            tamano=file_size
        )
    except FileNotFoundError:
        pass
    return redirect(url_for('listar'))

@app.route('/chat')
@login_required
def chat():
    # ✅ CORREGIDO: Logging de acceso al chat
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER ENTERED CHAT - SERVER MSG',
        nombre_archivo='chat_access',
        tamano=0
    )
    return render_template('chat.html', current_user=current_user)

# --- SOCKET.IO ---

# --- SOCKET.IO MEJORADO ---
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
def on_join(data):
    """✅ JOIN MEJORADO CON PROTECCIÓN DOS"""
    if not current_user.is_authenticated:
        return
    
    username = current_user.id
    room_code = data.get('room', '')[:20]  # ✅ LIMITAR LONGITUD
    password = data.get('password', '')[:100]  # ✅ LIMITAR LONGITUD
    client_id = request.sid
    
    # ✅ PROTECCIÓN DOS MEJORADA
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
def handle_message(data):
    """✅ MANEJO DE MENSAJES CON VALIDACIÓN"""
    if not current_user.is_authenticated:
        return
    
    username = current_user.id
    room = data.get('room', '')[:20]
    msg = data.get('msg', '')[:1000]  # ✅ LIMITAR LONGITUD MENSAJE
    
    # ✅ VALIDACIÓN CONTRA INYECCIÓN/SCRIPTS
    if not room or not msg.strip():
        return
    
    # ✅ SANITIZACIÓN BÁSICA
    msg = msg.replace('<', '&lt;').replace('>', '&gt;')
    
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

# --- INICIO MEJORADO ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    
    logger.log_archivo(
        usuario="SERVER",
        accion=f"SERVER_START_SECURE",
        nombre_archivo=SERVERFILE,
        tamano=0
    )
    
    print(f"🚀 PiChat Secure iniciando en puerto {port}")
    print("🔒 Características de seguridad activadas:")
    print("   - Rate Limiting (Flask-Limiter)")
    print("   - CORS Configurado")
    print("   - Protección contra fuerza bruta")
    print("   - Logging mejorado con buffer")
    print("   - Sanitización de inputs")
    print("   - Protección DoS en salas de chat")
    
    socketio.run(app, 
                host='0.0.0.0', 
                port=port, 
                debug=os.getenv('DEBUG', 'False').lower() == 'true')

application = app
