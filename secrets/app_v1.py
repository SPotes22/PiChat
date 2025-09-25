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
import time
import json
from argon2 import PasswordHasher
from src.services.logger_service import AdvancedLogger # ;) 
from flask import (
    Flask, request, jsonify, redirect, url_for,
    send_from_directory, render_template
)
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.utils import secure_filename
from flask_argon2 import Argon2


# --- CONFIGURACIÓN INICIAL ---
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*") # SocketIO envuelve a Flask
app.secret_key = os.environ.get("SECRET_KEY", "a-very-secret-key-for-dev")
argon2 = Argon2(app)
ph = PasswordHasher()
logger = AdvancedLogger()
SERVERFILE = 'server_hist.csv'

# Track intentos y verificación exitosa
room_attempts = {}
verified_sessions = {}  # Cache de sesiones verificadas

print("configuracion inicial completada ...")

# --- CONFIGURACIÓN DE CARPETAS ---
UPLOAD_FOLDER = './cuarentena'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

print("verificacion de archivos demo ...")

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

print("usuarios base generados...")
'''
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

print("usuarios demo creados ....")
'''
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

print("login initializied... Starting app....")
# --- RUTAS ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='LOGIN EXITOSO - SERVER MSG -',
            nombre_archivo=SERVERFILE # no hay, archivo pero inferimos que podemos poner la sala de chat en ese campo que tambien es cadena sjsj
            tamano=0 # pq xd, es ethereo.
        )

    if request.method == 'POST':
        user = request.form['usuario']
        password = request.form['clave']
        if user in users:
            try:
                ph.verify(users[user]['password'], password)
                login_user(Usuario(user, users[user]['role']))
                return redirect(url_for('inicio'))
            except Exception:
                # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
                logger.log_archivo(
                usuario=current_user.id,
                accion='LOGIN FAIL - GO TO  IT -',
                nombre_archivo=''#Aun no he hecho esto. del limiter,
                tamano='-1'# tambien es como cosa maluca para hacer despues entonces se marca como tal.
                )
        return render_template("login.html", error="Credenciales inválidas.")
    return render_template("login.html")

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='USER LOG OUT -  EXITED SESSION - SUCCCES. ',
            nombre_archivo='' # no hay, archivo pero inferimos que podemos poner {user_hist.csv}  en ese campo que tambien es cadena sjsj --> TODO
            tamano=0 # pq xd, es ethereo.
        )

    return redirect(url_for('login'))

@app.route('/inicio')
@login_required
def inicio():
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='USER LOGIN - SERVER MSG - SUCCES>',
            nombre_archivo='' # no hay, archivo pero inferimos que podemos poner el mismo {user_hist.csv} en ese campo que tambien es cadena sjsj --> TODO
            tamano=0 # pq xd, es ethereo.
        )

    return render_template('inicio.html', current_user=current_user)


# --- FUNCIONALIDAD DE ARCHIVOS ---
@app.route('/subir', methods=['GET', 'POST'])
@login_required
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
        # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='subir',
            nombre_archivo=filename,
            tamano=archivo.content_length
        ) # Clean. 25/9/25
        return redirect(url_for('listar'))
    return render_template("subir.html")

@app.route('/listar')
@login_required
def listar():
    archivos = os.listdir(UPLOAD_FOLDER)
    #✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='USER LISTS FILES FROM SERVER - SERVER MSG - SUCCESS.',
            nombre_archivo=room_code # no hay, archivo pero inferimos que podemos poner la sala de chat en ese campo que tambien es cadena sjsj
            tamano=0 # pq xd, es ethereo.
        )

    return render_template("listar.html", archivos=archivos)

@app.route('/descargar/<nombre>')
@login_required
def descargar(nombre):
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='USER DOWNLOADS FILE -- SERVER MSG -- SUCCESS. ',
            nombre_archivo=filename,
            tamano=0#i already know its from ' cuarentena/'
        )
    return send_from_directory(UPLOAD_FOLDER, nombre, as_attachment=True)

@app.route('/eliminar/<nombre>')
@login_required
def eliminar(nombre):
    if current_user.rol != 'administrator':
        return 'No tienes permiso para eliminar archivos', 403
    try:
        os.remove(os.path.join(UPLOAD_FOLDER, secure_filename(nombre)))
    except FileNotFoundError:
        pass

    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='ARCHIVO ELIMINADO - SERVER MSG -',
            nombre_archivo=filename,
            tamano="-1"# estamos usan csv, a quien le importa si no es el mismo type; para eso estan los data cleaners.
        )
    return redirect(url_for('listar'))

@app.route('/chat')
@login_required
def chat():
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='USER : Entro al chat. -- SERVER MSG --',
            nombre_archivo=filename,
            tamano=0# cambiar por hora exacta don datetime.now()

        )
    return render_template('chat.html', current_user=current_user)


# --- SOCKET.IO ---
chat_rooms = {}

@socketio.on('join')
def on_join(data):
    username = current_user.id
    room_code = data['room']
    password = data['password']
    is_group = data.get('is_group', False)
    
     # ⭐ PREVENCIÓN DoS: Rate limiting estricto
    attempt_key = f"{client_id}:{room_code}"
    current_time = time.time()

    # Limitar intentos: máximo 1 cada 2 segundos
    if attempt_key in room_attempts:
        last_attempt = room_attempts[attempt_key]['last_attempt']
        if current_time - last_attempt < 2:  # 2 segundos entre intentos
            send({'msg': 'Espera 2 segundos entre intentos.', 'type': 'error'})
            return

    # ⭐ CACHE: Si ya verificó correctamente, no recalcular Argon2
    session_key = f"{client_id}:{room_code}"
    if session_key in verified_sessions:
        if verified_sessions[session_key] == password:
            join_room(room_code)
            send({'msg': f"👋 {username} se ha unido.", 'user': 'Servidor'}, to=room_code)
            return print('SERVER - MSG -')

    if room_code not in chat_rooms:
        chat_rooms[room_code] = ph.hash(password)
    else:
        try:
            ph.verify(chat_rooms[room_code], password)
        except Exception: # argon2.exceptions.VerifyMismatchError
            send({'msg': 'Contraseña incorrecta.', 'type': 'error'})
            return

    join_room(room_code)
    send({'msg': f"👋 {username} se ha unido.", 'user': 'Servidor', 'is_group': is_group}, to=room_code)
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='SE UNIO A SALA.- USER.MSG NO GUARDADO -',
            nombre_archivo=room_code # no hay, archivo pero inferimos que podemos poner la sala de chat en ese campo que tambien es cadena sjsj
            tamano=0 # pq xd, es ethereo.
        )

@socketio.on('leave')
def on_leave(data):
    username = current_user.id
    room_code = data['room']
    leave_room(room_code)
    send({'msg': f"🚪 {username} ha salido.", 'user': 'Servidor'}, to=room_code)
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='SALIO DEL CHAT - END OF -Conversationid- SREVER MSG -',
            nombre_archivo=room_code # no hay, archivo pero inferimos que podemos poner la sala de chat en ese campo que tambien es cadena sjsj <- ademas queda muy sapo
            # dar el ID de la sala en pleno log.
            tamano=0 # pq xd, es ethereo.
        )


@socketio.on('message')
def handle_message(data):
    username = current_user.id
    room = data['room']
    msg = data['msg']
    is_group = data.get('is_group', False)
    send({'msg': msg, 'user': username, 'is_group': is_group}, to=room)
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario=current_user.id,
            accion='Envio - USER.MSG - (NO SE GAURDA)',
            nombre_archivo=room # no hay, archivo pero inferimos que podemos poner la sala de chat en ese campo que tambien es cadena sjsj
            tamano=0 # pq xd, es ethereo.
        )



# --- INICIO ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    socketio.run(app, host='0.0.0.0', port=port) # 👉 Para gunicorn/render
    print(f"app running at host : 0.0.0.0 and port {port}")
    # ✅ NUEVO: LOGGING DE ARCHIVO SUBIDO
        logger.log_archivo(
            usuario="SERVER",
            accion=f'SATART LISTEN AT '0.0.0.0:{port}' -- SERVER MSG -- ',
            nombre_archivo='Server_hist' # no hay, archivo pero inferimos que podemos poner {server HIST } en ese campo que tambien es cadena sjsj
            tamano=0 # pq xd, es ethereo.
        )

application = app
