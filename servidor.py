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
# 👇 esto siempre va primero
import eventlet
eventlet.monkey_patch()

import os
import json
from datetime import timedelta
from urllib.parse import urlparse
from werkzeug.middleware.proxy_fix import ProxyFix # <<< CORRECCIÓN 1

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
    if '://' not in o:
        o = 'https://' + o
    parsed = urlparse(o)
    netloc = parsed.netloc or parsed.path
    scheme = parsed.scheme or 'https'
    return f"{scheme}://{netloc}"

# ---------------------------
# CONFIG INICIAL
# ---------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

ALLOWED_TAGS = []
ALLOWED_ATTRS = {}
ALLOWED_PROTOCOLS = ['http', 'https']

app = Flask(__name__)
# <<< CORRECCIÓN 1: Indicar a Flask que confíe en el proxy de Render.
# Esto es VITAL para que Talisman y las cookies seguras funcionen en producción.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.secret_key = os.environ.get("SECRET_KEY", "dev_secret")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    # <<< CORRECCIÓN 2: 'Lax' es un valor más seguro y compatible para una aplicación web estándar.
    # 'None' es principalmente para iframes o APIs consumidas desde otros dominios.
    SESSION_COOKIE_SAMESITE='Lax',
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
# El manage_session=False puede dar problemas, es mejor dejar que Flask-Login y SocketIO se sincronicen.
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS)

# ---------------------------
# CSRF: init
# ---------------------------
csrf = CSRFProtect(app)
# La exención para socketio ya no es tan necesaria si las cookies y el proxy están bien configurados.
# Flask-WTF >1.0 integra mejor con Socket.IO, pero si da problemas, puedes eximir la ruta específica.
# csrf.exempt('flask_socketio.SocketIO')


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
    # force_https ahora funcionará correctamente gracias a ProxyFix
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    frame_options="DENY",
    referrer_policy="no-referrer",
    session_cookie_secure=True,
    content_security_policy_nonce_in=['script-src'],
)

# ... El resto de tu código (RATE LIMITER, UPLOAD, AUTH, RUTAS, etc.) permanece igual ...
# ¡SOLO RECUERDA AÑADIR EL TOKEN CSRF A TUS FORMULARIOS HTML!

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

# --- (El resto de tu código sigue aquí sin cambios) ---
# ...
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
    
# ... y así sucesivamente con el resto de tus rutas y lógica de Socket.IO ...

# ---------------------------
# ENTRYPOINTS
# ---------------------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    # No es necesario especificar el host como '0.0.0.0' cuando se usa eventlet con gunicorn en producción.
    # Gunicorn se encarga de eso.
    socketio.run(app, port=port)

# para Gunicorn / Render / Railway
application = app
# No es necesario re-inicializar socketio aquí.
# application = socketio