'''
PiChat - Chat Corporativo Almacenamiento-Básico en Red
Copyright (C) 2025 Santiago Potes Giraldo
SPDX-License-Identifier: GPL-3.0-or-later

Este archivo es parte de PiChat.

PiChat is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

'''
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory, render_template
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from flask_argon2 import Argon2
import os, json
from argon2 import PasswordHasher
import logging
from logging.handlers import RotatingFileHandler
from datetime import timedelta
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
from flask_wtf import CSRFProtect


# --- CONFIGURACIÓN INICIAL ---

ALLOWED_TAGS = []           # sin HTML permitido
ALLOWED_ATTRS = {}
ALLOWED_PROTOCOLS = ['http', 'https']

app = Flask(__name__)
#CSRFProtect(app)

csrf = CSRFProtect()
csrf.init_app(app)

# Excluir sockets del CSRF
csrf.exempt(socketio_app)

#socketio = SocketIO(app, cors_allowed_origins="*")  # SocketIO envuelve a Flask
app.secret_key = os.environ.get("SECRET_KEY") 

app.config.update(
    SESSION_COOKIE_SECURE=True,       # solo por HTTPS
    SESSION_COOKIE_HTTPONLY=True,     # no accesible por JS
    SESSION_COOKIE_SAMESITE=None,    # o "Strict" si no integras con otros dominios
    REMEMBER_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,  # 25MB uploads
)

# Limitar orígenes del socket (quitar el "*")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "https://pichat-k0bi.onrender.com/chat").split(",")
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS)  # evita CSRF en websockets


argon2 = Argon2(app)
ph = PasswordHasher()

# Content Security Policy estricta (ajústala a tus assets/CDNs reales)
csp = {
    'default-src': "'self'",
    'img-src': "'self' data:",
    'style-src': "'self' 'unsafe-inline'",   # mejor sin 'unsafe-inline' si usas sólo archivos .css
    'script-src': "'self'",                   # sin inline scripts
    'connect-src': "'self' wss://pichat-k0bi.onrender.com",
}

# Fuerza HTTPS + headers seguros
Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    frame_options="DENY",
    referrer_policy="no-referrer",
    session_cookie_secure=True,
    content_security_policy_nonce_in=['script-src'],
)

# Rate limiting global y por endpoint
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"])

# --- CONFIGURACIÓN DE CARPETAS ---
UPLOAD_FOLDER = './cuarentena'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- USUARIOS BASE ---
users = {
    os.getenv("ADMIN_USER", "admin"): {
        "password": ph.hash(os.getenv("ADMIN_PASS", "admin123")),
        "role": "administrator"
    },
    os.getenv("CLIENT_USER", "cliente"): {
        "password": ph.hash(os.getenv("CLIENT_PASS", "cliente123")),
        "role": "cliente"
    },
    os.getenv("USR_USER", "usuario"): {
        "password": ph.hash(os.getenv("USR_PASS", "usuario123")),
        "role": "usuario"
    }
}

# --- DEMO USERS DESDE ENV ---
try:
    demo_users_env = os.getenv("DEMO_USERS", "[]")
    demo_users = json.loads(demo_users_env)
    for u in demo_users:
        users[u["username"]] = {
            "password": ph.hash(u["password"]),
            "role": u.get("role", "usuario")
        }
except Exception as e:
    print(f"[WARN] No se pudieron cargar demo_users: {e}")

# --- LOGIN MANAGER ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Usuario(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.rol = role

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return Usuario(user_id, users[user_id]['role'])
    return None

# --- RUTAS ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute; 20/hour")  # fuerza bruta
def login():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        user = (request.form.get('usuario') or "")[:64]
        password = (request.form.get('clave') or "")[:256]

        if user in users:
            try:
                ph.verify(users[user]['password'], password)
                login_user(Usuario(user, users[user]['role']))
                return redirect(url_for('inicio'))
            except Exception:
                pass

        # mensaje genérico: no reveles si el usuario existe
        return render_template("login.html", error="Credenciales inválidas.")
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/inicio')
@login_required
def inicio():
    return render_template('inicio.html', current_user=current_user)

# --- FUNCIONALIDAD DE ARCHIVOS ---
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif'}

def allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS

@app.route('/subir', methods=['GET', 'POST'])
@login_required
@limiter.limit("20/hour")
def subir():
    if current_user.rol == 'usuario':
        return 'No tienes permiso para subir archivos', 403

    if request.method == 'POST':
        f = request.files.get('archivo')
        if not f or f.filename == '':
            return 'No se seleccionó archivo', 400

        filename = secure_filename(f.filename)
        if not allowed_file(filename):
            return 'Tipo de archivo no permitido', 400

        f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('listar'))
    return render_template("subir.html")


@app.route('/listar')
@login_required
def listar():
    archivos = os.listdir(UPLOAD_FOLDER)
    return render_template("listar.html", archivos=archivos)

@app.route('/descargar/<nombre>')
@login_required
def descargar(nombre):
    return send_from_directory(UPLOAD_FOLDER, nombre, as_attachment=True)

@app.route('/eliminar/<nombre>', methods=['POST'])  # evita GET peligrosos
@login_required
def eliminar(nombre):
    if current_user.rol != 'administrator':
        return 'No tienes permiso para eliminar archivos', 403
    safe = secure_filename(nombre)
    target = os.path.join(UPLOAD_FOLDER, safe)
    if os.path.commonpath([os.path.abspath(target), os.path.abspath(UPLOAD_FOLDER)]) != os.path.abspath(UPLOAD_FOLDER):
        return "Ruta inválida", 400
    try:
        os.remove(target)
    except FileNotFoundError:
        pass
    return redirect(url_for('listar'))


@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', current_user=current_user)

# --- SOCKET.IO ---
chat_rooms = {}

@socketio.on('join')
@limiter.limit("1/minute")
def on_join(data):
    username = current_user.id
    room_code = (data.get('room') or "")[:64]
    password = (data.get('password') or "")[:128]
    is_group = bool(data.get('is_group', False))

    if not room_code or not password:
        send({'msg': 'Parámetros inválidos.', 'type': 'error'})
        return

    if room_code not in chat_rooms:
        chat_rooms[room_code] = argon2.generate_password_hash(password)
    else:
        if not argon2.check_password_hash(chat_rooms[room_code], password):
            send({'msg': 'Acceso denegado.', 'type': 'error'})
            return

    join_room(room_code)
    send({'msg': f"👋 {username} se ha unido.", 'user': 'Servidor', 'is_group': is_group}, to=room_code)


@socketio.on('leave')
def on_leave(data):
    username = current_user.id
    room_code = data['room']
    leave_room(room_code)
    send({'msg': f"🚪 {username} ha salido.", 'user': 'Servidor'}, to=room_code)

@socketio.on('message')
@limiter.limit("1/minute")   # evita spam de mensajes
def handle_message(data):
    username = current_user.id
    room = (data.get('room') or "")[:64]
    raw_msg = data.get('msg')
    msg = clean_text(raw_msg)
    is_group = bool(data.get('is_group', False))

    # opcional: valida que el usuario esté realmente en esa room

    send({'msg': msg, 'user': username, 'is_group': is_group}, to=room)


if not app.debug:
    handler = RotatingFileHandler('app.log', maxBytes=5_000_000, backupCount=3)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)

@app.errorhandler(400)
def bad_request(e): return "Solicitud inválida", 400

@app.errorhandler(403)
def forbidden(e): return "Prohibido", 403

@app.errorhandler(404)
def not_found(e): return "No encontrado", 404

@app.errorhandler(500)
def server_error(e): 
    app.logger.exception("Error 500")
    return "Error del servidor", 500
@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))

def clean_text(s: str) -> str:
    s = (s or "")[:2000]  # límite de tamaño de mensaje
    return bleach.clean(s, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, protocols=ALLOWED_PROTOCOLS, strip=True)



# --- INICIO ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host='0.0.0.0', port=port)

# 👉 Para gunicorn/render
application = app
socketio_app = socketio