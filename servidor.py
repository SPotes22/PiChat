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
import os
import json
from datetime import timedelta
from urllib.parse import urlparse

from flask import Flask, request, jsonify, redirect, url_for, send_from_directory, render_template
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from flask_argon2 import Argon2
from argon2 import PasswordHasher
import logging
from logging.handlers import RotatingFileHandler
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
from flask_wtf import CSRFProtect

# ---------------------------
# Utiles para sanitizar / orígenes
# ---------------------------
def normalize_origin(o: str):
    if not o:
        return None
    o = o.strip()
    # quitar path si lo puso (p.ej. "https://mi.app/chat")
    if '://' not in o:
        # permitir que pasen dominios sin esquema
        o = 'https://' + o
    parsed = urlparse(o)
    netloc = parsed.netloc or parsed.path
    scheme = parsed.scheme or 'https'
    return f"{scheme}://{netloc}"

# ---------------------------
# CONFIG INICIAL
# ---------------------------
ALLOWED_TAGS = []
ALLOWED_ATTRS = {}
ALLOWED_PROTOCOLS = ['http', 'https']

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=None,   # importante para que cookies se envíen con websocket handshakes cross-site
    REMEMBER_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
)

# ---------------------------
# ALLOWED ORIGINS: parsear desde env para no hardcodear paths
# ---------------------------
_default_origins = "https://pichat-k0bi.onrender.com,http://localhost:10000"
origins_env = os.environ.get("ALLOWED_ORIGINS", _default_origins)
ALLOWED_ORIGINS = []
for part in origins_env.split(","):
    n = normalize_origin(part)
    if n:
        ALLOWED_ORIGINS.append(n)

# socketio: allow the parsed origins (no paths)
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, manage_session=False)

# ---------------------------
# CSRF: init y EXEMPT para socketio (handshake)
# ---------------------------
csrf = CSRFProtect()
csrf.init_app(app)

# intentamos eximir SocketIO del CSRF (lo ideal es eximir la ruta /socket.io)
# Si no funcionara por alguna razón, el try/except evita romper el boot.
try:
    csrf.exempt(socketio)  # normalmente esto evita que flask-wtf valide el handshake
except Exception:
    try:
        csrf.exempt('socketio')
    except Exception:
        pass

# ---------------------------
# TALISMAN / CSP: construir connect-src dinámicamente a partir de ALLOWED_ORIGINS
# ---------------------------
wss_origins = []
for o in ALLOWED_ORIGINS:
    if o.startswith("https://"):
        wss_origins.append(o.replace("https://", "wss://"))
    elif o.startswith("http://"):
        wss_origins.append(o.replace("http://", "ws://"))
    else:
        wss_origins.append(o)

connect_src_value = "'self'"
if wss_origins:
    connect_src_value += " " + " ".join(wss_origins)

csp = {
    'default-src': "'self'",
    'img-src': "'self' data:",
    'style-src': "'self' 'unsafe-inline'",
    'script-src': "'self'",
    'connect-src': connect_src_value,
}

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

# ---------------------------
# RATE LIMITER
# ---------------------------
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"])

# ---------------------------
# ARCHIVOS / UPLOAD
# ---------------------------
UPLOAD_FOLDER = './cuarentena'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif'}

def allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS

# ---------------------------
# AUTH / USERS (demo)
# ---------------------------
argon2 = Argon2(app)
ph = PasswordHasher()

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

# demo users desde env (JSON)
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

# ---------------------------
# RUTAS / ENDPOINTS HTTP
# ---------------------------
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute; 20/hour")
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

@app.route('/eliminar/<nombre>', methods=['POST'])
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

# ---------------------------
# SOCKET.IO EVENTS
# ---------------------------
chat_rooms = {}

@socketio.on('join')
@limiter.limit("1/minute")
def on_join(data):
    # current_user debería venir vía cookie de sesión si SameSite y CORS correctos
    username = getattr(current_user, "id", None)
    if not username:
        send({'msg': 'Usuario no autenticado.', 'type': 'error'})
        return

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
    username = getattr(current_user, "id", None) or "Anon"
    room_code = data.get('room')
    if room_code:
        leave_room(room_code)
        send({'msg': f"🚪 {username} ha salido.", 'user': 'Servidor'}, to=room_code)

@socketio.on('message')
@limiter.limit("1/minute")
def handle_message(data):
    username = getattr(current_user, "id", None) or "Anon"
    room = (data.get('room') or "")[:64]
    raw_msg = data.get('msg')
    msg = clean_text(raw_msg)
    is_group = bool(data.get('is_group', False))

    send({'msg': msg, 'user': username, 'is_group': is_group}, to=room)

# ---------------------------
# LOGGING & ERRORES
# ---------------------------
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
    s = (s or "")[:2000]
    return bleach.clean(s, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, protocols=ALLOWED_PROTOCOLS, strip=True)

# ---------------------------
# ENTRYPOINTS
# ---------------------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host='0.0.0.0', port=port)

# para Gunicorn / Render / Railway
application = app
socketio_app = socketio