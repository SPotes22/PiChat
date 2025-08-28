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
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory, render_template from flask_socketio import SocketIO, join_room, leave_room, send from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user from werkzeug.utils import secure_filename from flask_argon2 import Argon2 import os, json from argon2 import PasswordHasher 
# --- CONFIGURACIÓN INICIAL --- 
app = Flask(__name__) socketio = SocketIO(app, cors_allowed_origins="*") 
# SocketIO envuelve a Flask
app.secret_key = os.environ.get("SECRET_KEY", "a-very-secret-key-for-dev") argon2 = Argon2(app) ph = PasswordHasher() 
# --- CONFIGURACIÓN DE CARPETAS --- 
UPLOAD_FOLDER = './cuarentena' os.makedirs(UPLOAD_FOLDER, exist_ok=True) app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # --- USUARIOS BASE --- 
users = { os.getenv("ADMIN_USER", "admin"): { "password": ph.hash(os.getenv("ADMIN_PASS", "admin123")), "role": "administrator" }, os.getenv("CLIENT_USER", "cliente"): { "password": ph.hash(os.getenv("CLIENT_PASS", "cliente123")), "role": "cliente" }, os.getenv("USR_USER", "usuario"): { "password": ph.hash(os.getenv("USR_PASS", "usuario123")), "role": "usuario" } } # --- DEMO USERS DESDE ENV --- 
try: demo_users_env = os.getenv("DEMO_USERS", "[]") demo_users = json.loads(demo_users_env) for u in demo_users: users[u["username"]] = { "password": ph.hash(u["password"]), "role": u.get("role", "usuario") } except Exception as e: print(f"[WARN] No se pudieron cargar demo_users: {e}") 
# --- LOGIN MANAGER --- 
login_manager = LoginManager(app) login_manager.login_view = 'login' class Usuario(UserMixin): def __init__(self, username, role): self.id = username self.rol = role @login_manager.user_loader def load_user(user_id): if user_id in users: return Usuario(user_id, users[user_id]['role']) return None 
# --- RUTAS ---
@app.route('/') def home(): if current_user.is_authenticated: return redirect(url_for('inicio')) return redirect(url_for('login')) @app.route('/login', methods=['GET', 'POST']) def login(): if current_user.is_authenticated: return redirect(url_for('inicio')) if request.method == 'POST': user = request.form['usuario'] password = request.form['clave'] if user in users: try: ph.verify(users[user]['password'], password) login_user(Usuario(user, users[user]['role'])) return redirect(url_for('inicio')) except Exception: pass return render_template("login.html", error="Credenciales inválidas.") return render_template("login.html") @app.route('/logout') @login_required def logout(): logout_user() return redirect(url_for('login')) @app.route('/inicio') @login_required def inicio(): return render_template('inicio.html', current_user=current_user) 
# --- FUNCIONALIDAD DE ARCHIVOS --- 
@app.route('/subir', methods=['GET', 'POST']) @login_required def subir(): if current_user.rol == 'usuario': return 'No tienes permiso para subir archivos', 403 if request.method == 'POST': if 'archivo' not in request.files: return 'No se encontró el archivo', 400 archivo = request.files['archivo'] if archivo.filename == '': return 'No se seleccionó ningún archivo', 400 filename = secure_filename(archivo.filename) archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename)) return redirect(url_for('listar')) return render_template("subir.html") @app.route('/listar') @login_required def listar(): archivos = os.listdir(UPLOAD_FOLDER) return render_template("listar.html", archivos=archivos) @app.route('/descargar/<nombre>') @login_required def descargar(nombre): return send_from_directory(UPLOAD_FOLDER, nombre, as_attachment=True) @app.route('/eliminar/<nombre>') @login_required def eliminar(nombre): if current_user.rol != 'administrator': return 'No tienes permiso para eliminar archivos', 403 try: os.remove(os.path.join(UPLOAD_FOLDER, secure_filename(nombre))) except FileNotFoundError: pass return redirect(url_for('listar')) @app.route('/chat') @login_required def chat(): return render_template('chat.html', current_user=current_user) 
# --- SOCKET.IO --- 
chat_rooms = {} @socketio.on('join') def on_join(data): username = current_user.id room_code = data['room'] password = data['password'] is_group = data.get('is_group', False) if room_code not in chat_rooms: chat_rooms[room_code] = argon2.generate_password_hash(password) else: if not argon2.check_password_hash(chat_rooms[room_code], password): send({'msg': 'Contraseña incorrecta.', 'type': 'error'}) return join_room(room_code) send({'msg': f"👋 {username} se ha unido.", 'user': 'Servidor', 'is_group': is_group}, to=room_code) @socketio.on('leave') def on_leave(data): username = current_user.id room_code = data['room'] leave_room(room_code) send({'msg': f"🚪 {username} ha salido.", 'user': 'Servidor'}, to=room_code) @socketio.on('message') def handle_message(data): username = current_user.id room = data['room'] msg = data['msg'] is_group = data.get('is_group', False) send({'msg': msg, 'user': username, 'is_group': is_group}, to=room) 
# --- INICIO --- 
if __name__ == '__main__': port = int(os.environ.get("PORT", 10000)) socketio.run(app, host='0.0.0.0', port=port) # 👉 Para gunicorn/render 
application = app