'''
PiChat - Chat Corporativo - VERSIÓN HÍBRIDA FUNCIONAL
Copyright (C) 2025 Santiago Potes Giraldo
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

# configuracion de usuarios demo
# --- HOTFIX TEMPORAL: Convertir tu JSON a la estructura nueva ---
import json

# Tu environment variable actual

users_json = os.getenv("USERS_JSON_LAST", "[]")

# Convertir lista de diccionarios a diccionario de diccionarios
def load_users_from_env():
    try:
        users_list = json.loads(users_json)
        users = {}
    
        for user in users_list:
            username = user['username']
            users[username] = {
                "password": ph.hash(user['password']),  # ✅ IMPORTANTE: Hashear!
                "role": user['role'],
                "failed_attempts": 0,
                "last_attempt": None
            }
    
    print(f"✅ Usuarios convertidos: {list(users.keys())}")
    
    except Exception as e:
        print(f"❌ Error convirtiendo usuarios: {e}")
        # Fallback a usuarios básicos
        users = {
            "admin": {
            "password": ph.hash("admin123"),
            "role": "administrator",
            "failed_attempts": 0,
            "last_attempt": None
            },
            "usuario": {
            "password": ph.hash("usuario123"), 
            "role": "usuario",
            "failed_attempts": 0,
            "last_attempt": None
         }
        }
# --- USUARIOS CARGADOS CORRECTAMENTE ---
users = load_users_from_env()

print(f"✅ Usuarios cargados: {list(users.keys())}")

# ✅ IMPORTAR MÓDULOS QUE SÍ FUNCIONAN
from src.utils.security import (
    check_brute_force_protection, 
    increment_failed_attempt, 
    reset_failed_attempts,
    setup_brute_force_protection
)
from src.utils.input_sanitizer import (
    sanitize_input, sanitize_filename, 
    sanitize_message, sanitize_room_code
)

# --- CONFIGURACIÓN INICIAL ---
UPLOAD_FOLDER = './cuarentena'
app = Flask(__name__)

# ✅ LIMITER INICIALIZADO PRIMERO (IMPORTANTE!)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="moving-window"
)

# ✅ CORS CONFIGURADO SEGURO
CORS(app, origins=[
    "http://localhost:3000",
    "https://tudominio.com", 
    os.getenv("ALLOWED_ORIGINS", "http://localhost:8080")
], supports_credentials=True)

socketio = SocketIO(app, 
    cors_allowed_origins="*",
    async_mode='threading',
    logger=True,
    engineio_logger=False
)

app.secret_key = os.environ.get("SECRET_KEY", "a-very-secret-key-for-dev")
ph = PasswordHasher()

# ✅ LOGGER MEJORADO
logger = AdvancedLogger(
    logs_dir='./logs',
    max_file_size_mb=10,
    buffer_size=100
)

SERVERFILE = 'server_hist.csv'

# --- CONFIGURACIÓN SEGURIDAD ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    UPLOAD_FOLDER=UPLOAD_FOLDER
)

print("Configuración de seguridad inicial completada ...")

# --- CARPETA UPLOADS ---
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- USUARIOS BASE ---
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

# ✅ CONFIGURAR PROTECCIÓN FUERZA BRUTA (MÓDULO FUNCIONAL)
setup_brute_force_protection(users)

print("Sistema de autenticación hardening inicializado...")

# --- LOGIN MANAGER ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

class Usuario(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.rol = role

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return Usuario(user_id, users[user_id]['role'])
    return None

# --- RUTAS MEJORADAS CON MÓDULOS ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", deduct_when=lambda response: response.status_code != 200)
def login():
    """✅ LOGIN MEJORADO CON MÓDULO DE SEGURIDAD"""
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
        
        # ✅ PROTECCIÓN FUERZA BRUTA (MÓDULO)
        if check_brute_force_protection(user, users):
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
                # ✅ RESETEO DE INTENTOS (MÓDULO)
                reset_failed_attempts(user, users)
                
                login_user(Usuario(user, users[user]['role']))
                
                logger.log_archivo(
                    usuario=user,
                    accion='LOGIN_EXITOSO',
                    nombre_archivo=SERVERFILE,
                    tamano=0
                )
                return redirect(url_for('inicio'))
            except Exception as e:
                # ✅ INCREMENTO DE INTENTOS (MÓDULO)
                increment_failed_attempt(user, users)
                
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

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
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
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER ACCESS INICIO - SERVER MSG - SUCCESS',
        nombre_archivo='user_hist.csv',
        tamano=0
    )
    return render_template('inicio.html', current_user=current_user)

# --- FUNCIONALIDAD DE ARCHIVOS CON MÓDULOS ---
@app.route('/subir', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute")
def subir():
    """✅ SUBIR ARCHIVOS CON SANITIZACIÓN MODULAR"""
    if current_user.rol == 'usuario':
        return 'No tienes permiso para subir archivos', 403
    
    if request.method == 'POST':
        if 'archivo' not in request.files:
            return 'No se encontró el archivo', 400
        
        archivo = request.files['archivo']
        if archivo.filename == '':
            return 'No se seleccionó ningún archivo', 400
        
        # ✅ SANITIZACIÓN MODULAR
        filename = sanitize_filename(archivo.filename)
        safe_filename = secure_filename(filename)
        
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], safe_filename))

        logger.log_archivo(
            usuario=current_user.id,
            accion='subir',
            nombre_archivo=safe_filename,
            tamano=archivo.content_length
        )
        return redirect(url_for('listar'))
    
    return render_template("subir.html")

@app.route('/listar')
@login_required
def listar():
    archivos = os.listdir(UPLOAD_FOLDER)

    logger.log_archivo(
        usuario=current_user.id,
        accion='USER LISTS FILES FROM SERVER - SUCCESS',
        nombre_archivo='file_list',
        tamano=len(archivos)
    )
    return render_template("listar.html", archivos=archivos)

@app.route('/descargar/<nombre>')
@login_required
@limiter.limit("10 per minute")
def descargar(nombre):
    # ✅ SANITIZACIÓN MODULAR
    safe_filename = sanitize_filename(nombre)
    
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    logger.log_archivo(
        usuario=current_user.id,
        accion='USER DOWNLOADS FILE - SUCCESS',
        nombre_archivo=safe_filename,
        tamano=file_size
    )
    return send_from_directory(UPLOAD_FOLDER, safe_filename, as_attachment=True)

@app.route('/eliminar/<nombre>')
@login_required
@limiter.limit("3 per minute")
def eliminar(nombre):
    if current_user.rol != 'administrator':
        return 'No tienes permiso para eliminar archivos', 403
    
    try:
        # ✅ SANITIZACIÓN MODULAR
        safe_filename = sanitize_filename(nombre)
        file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else -1
        os.remove(file_path)

        logger.log_archivo(
            usuario=current_user.id,
            accion='ARCHIVO ELIMINADO - SUCCESS',
            nombre_archivo=safe_filename,
            tamano=file_size
        )
    except FileNotFoundError:
        pass
    return redirect(url_for('listar'))

@app.route('/chat')
@login_required
def chat():
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER ENTERED CHAT - SERVER MSG',
        nombre_archivo='chat_access',
        tamano=0
    )
    return render_template('chat.html', current_user=current_user)

# --- SOCKET.IO MEJORADO CON MÓDULOS ---
chat_rooms = {}
room_attempts = {}
verified_sessions = {}

@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False
    logger.log_chat(
        usuario=current_user.id,
        accion='SOCKET_CONNECT',
        sala='system',
        tamano_mensaje=0
    )

@socketio.on('disconnect')
def handle_disconnect():
    logger.log_chat(
        usuario=current_user.id if current_user.is_authenticated else 'unknown',
        accion='SOCKET_DISCONNECT',
        sala='system',
        tamano_mensaje=0
    )

@socketio.on('join')
def on_join(data):
    """✅ JOIN CON SANITIZACIÓN MODULAR"""
    if not current_user.is_authenticated:
        return
    
    username = current_user.id
    # ✅ SANITIZACIÓN MODULAR
    room_code = sanitize_room_code(data.get('room', ''))
    password = data.get('password', '')[:100]
    client_id = request.sid
    
    # ... (resto del código igual pero usando room_code sanitizado)
    
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
    """✅ MENSAJES CON SANITIZACIÓN MODULAR"""
    if not current_user.is_authenticated:
        return
    
    username = current_user.id
    room = sanitize_room_code(data.get('room', ''))
    # ✅ SANITIZACIÓN MODULAR
    msg = sanitize_message(data.get('msg', ''))
    
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

# --- INICIO ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    
    logger.log_archivo(
        usuario="SERVER",
        accion=f"SERVER_START_HYBRID_SECURE",
        nombre_archivo=SERVERFILE,
        tamano=0
    )
    
    print(f"🚀 PiChat Hybrid Secure iniciando en puerto {port}")
    print("🔒 Características activadas:")
    print("   - Rate Limiting FUNCIONAL")
    print("   - Módulos de seguridad")
    print("   - Sanitización modular")
    print("   - Logger con buffer")
    
    socketio.run(app, 
                host='0.0.0.0', 
                port=port, 
                debug=os.getenv('DEBUG', 'False').lower() == 'true')

application = app
