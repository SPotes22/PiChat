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
import os

# --- CONFIGURACIÓN INICIAL ---
app = Flask(__name__)
# Se recomienda usar una variable de entorno para la clave secreta
app.secret_key = os.environ.get("SECRET_KEY", "a-very-secret-key-for-dev") 
argon2 = Argon2(app)
socketio = SocketIO(app)

# --- CONFIGURACIÓN DE CARPETAS Y USUARIOS ---
UPLOAD_FOLDER = './cuarentena'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# En un entorno de producción, las contraseñas nunca deben estar hardcodeadas.
# Se generan hashes para las contraseñas por defecto.
usuarios = {
    'admin': {'password': argon2.generate_password_hash('admin123'), 'rol': 'administrator'},
    'cliente': {'password': argon2.generate_password_hash('cliente123'), 'rol': 'cliente'},
    'usuario': {'password': argon2.generate_password_hash('usuario123'), 'rol': 'usuario'},
}

# --- GESTIÓN DE LOGIN Y USUARIOS ---
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirige a /login si no está autenticado

class Usuario(UserMixin):
    def __init__(self, username):
        self.id = username
        self.rol = usuarios[username]['rol']

@login_manager.user_loader
def load_user(user_id):
    if user_id in usuarios:
        return Usuario(user_id)
    return None

# --- RUTAS WEB (VISTAS) ---

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
    if request.method == 'POST':
        user = request.form['usuario']
        password = request.form['clave']
        if user in usuarios and argon2.check_password_hash(usuarios[user]['password'], password):
            login_user(Usuario(user))
            return redirect(url_for('inicio'))
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

# --- FUNCIONALIDAD DE ARCHIVOS (MicroNAS) ---

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
        # Audit file -> I only trust UTF-8 (Concepto)
        # Aquí iría la lógica para validar el tipo de archivo antes de guardarlo.
        filename = secure_filename(archivo.filename)
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
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

@app.route('/eliminar/<nombre>')
@login_required
def eliminar(nombre):
    if current_user.rol != 'administrator':
        return 'No tienes permiso para eliminar archivos', 403
    try:
        os.remove(os.path.join(UPLOAD_FOLDER, secure_filename(nombre)))
    except FileNotFoundError:
        pass # Ignorar si el archivo no existe
    return redirect(url_for('listar'))

# --- RUTA PARA LA INTERFAZ DEL CHAT ---
@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', current_user=current_user)


# --- LÓGICA DEL SERVIDOR DE CHAT CON SOCKET.IO ---

# Almacenamiento en memoria para las salas y contraseñas (MVP)
# En un sistema real, esto debería estar en una base de datos.
chat_rooms = {} 

@socketio.on('join')
def on_join(data):
    """
    Unirse a una sala de chat.
    """
    username = current_user.id
    room_code = data['room']
    password = data['password']
    is_group = data.get('is_group', False)
    
    # Lógica de "candado" y contraseña
    if room_code not in chat_rooms:
        chat_rooms[room_code] = argon2.generate_password_hash(password)
        room_owner = True
    else:
        room_owner = False
        if not argon2.check_password_hash(chat_rooms[room_code], password):
            send({'msg': 'Contraseña de la sala incorrecta.', 'type': 'error'})
            return

    join_room(room_code)
    
    # Notificar a la sala que un nuevo usuario se ha unido
    message_data = {
        'msg': f"👋 {username} se ha unido a la sala.",
        'user': 'Servidor',
        'is_group': is_group
    }
    send(message_data, to=room_code)


@socketio.on('leave')
def on_leave(data):
    """
    Salir de una sala de chat.
    """
    username = current_user.id
    room_code = data['room']
    is_group = data.get('is_group', False)

    leave_room(room_code)
    
    message_data = {
        'msg': f"🚪 {username} ha salido de la sala.",
        'user': 'Servidor',
        'is_group': is_group
    }
    send(message_data, to=room_code)


@socketio.on('message')
def handle_message(data):
    """
    Recibir y reenviar mensajes.
    """
    username = current_user.id
    room = data['room']
    message = data['msg']
    is_group = data.get('is_group', False)
    
    # No guardar mensajes si es un chat grupal
    if is_group:
        # El mensaje es efímero, solo se reenvía
        pass
    else:
        # Aquí iría la lógica para guardar el mensaje en una base de datos o archivo
        # Para el MVP, simplemente lo reenviamos.
        pass
        
    response_data = {
        'msg': message,
        'user': username,
        'is_group': is_group
    }
    
    send(response_data, to=room)


# --- INICIO DE LA APLICACIÓN ---
if __name__ == '__main__':
    # Usar host='0.0.0.0' para que sea accesible en la red local.
    # El puerto 8000 es el principal. Otros servicios podrían correr en otros puertos
    # usando el concepto de 'administrador_hilos.py' si fuera necesario.
    socketio.run(app, host='0.0.0.0', port=8000, debug=True)
