# src/routes/auth_routes.py
from flask import Blueprint, request, render_template, redirect, url_for
from flask_login import login_user, logout_user, current_user
from flask_limiter.util import get_remote_address

from src.utils.security import (
    check_brute_force_protection, 
    increment_failed_attempt, 
    reset_failed_attempts
)
from src.services.logger_service import AdvancedLogger

auth_bp = Blueprint('auth', __name__)

# Esto se inicializará en app.py
users = {}
logger = None
limiter = None
ph = None

def init_auth_routes(users_dict, logger_instance, limiter_instance, password_hasher):
    """Inicializar dependencias de las rutas de auth"""
    global users, logger, limiter, ph
    users = users_dict
    logger = logger_instance
    limiter = limiter_instance
    ph = password_hasher

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", deduct_when=lambda response: response.status_code != 200)
def login():
    if current_user.is_authenticated:
        logger.log_archivo(
            usuario=current_user.id,
            accion='LOGIN_REDIRECT_ALREADY_AUTH',
            nombre_archivo='server_hist.csv',
            tamano=0
        )
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        user = request.form['usuario']
        password = request.form['clave']
        
        # Protección fuerza bruta
        if check_brute_force_protection(user, users):
            logger.log_archivo(
                usuario=user,
                accion='LOGIN_BLOCKED_BRUTE_FORCE',
                nombre_archivo='server_hist.csv',
                tamano=-1
            )
            return render_template("login.html", 
                                error="Demasiados intentos fallidos. Espere 15 minutos.")
        
        if user in users:
            try:
                ph.verify(users[user]['password'], password)
                # Reseteo de intentos al éxito
                reset_failed_attempts(user, users)
                
                from app import Usuario  # Importar aquí para evitar circular imports
                login_user(Usuario(user, users[user]['role']))
                
                logger.log_archivo(
                    usuario=user,
                    accion='LOGIN_EXITOSO',
                    nombre_archivo='server_hist.csv',
                    tamano=0
                )
                return redirect(url_for('inicio'))
            except Exception as e:
                # Incremento de intentos fallidos
                increment_failed_attempt(user, users)
                
                logger.log_archivo(
                    usuario=user,
                    accion=f'LOGIN_FALLIDO_ATTEMPT_{users[user]["failed_attempts"]}',
                    nombre_archivo='server_hist.csv',
                    tamano=-1
                )
        else:
            logger.log_archivo(
                usuario=user,
                accion='LOGIN_USUARIO_NO_EXISTE',
                nombre_archivo='server_hist.csv',
                tamano=-1
            )
            
        return render_template("login.html", error="Credenciales inválidas.")
    return render_template("login.html")

@auth_bp.route('/logout', methods=['GET','POST'])
def logout():
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER LOG OUT - EXITED SESSION - SUCCESS',
        nombre_archivo='user_hist.csv',
        tamano=0
    )
    logout_user()
    return redirect(url_for('auth.login'))
