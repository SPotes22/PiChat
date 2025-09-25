# src/routes/chat_routes.py
from flask import Blueprint, render_template
from flask_login import login_required, current_user

from src.services.logger_service import AdvancedLogger

chat_bp = Blueprint('chat', __name__)

# Dependencias a inicializar
logger = None

def init_chat_routes(logger_instance):
    """Inicializar dependencias de las rutas de chat"""
    global logger
    logger = logger_instance

@chat_bp.route('/chat')
@login_required
def chat():
    """Página principal del chat"""
    # Logging de acceso al chat
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER ENTERED CHAT - SERVER MSG',
        nombre_archivo='chat_access',
        tamano=0
    )
    
    logger.log_chat(
        usuario=current_user.id,
        accion='PAGE_ACCESS',
        sala='main',
        tamano_mensaje=0
    )
    
    return render_template('chat.html', current_user=current_user)

@chat_bp.route('/inicio')
@login_required
def inicio():
    """Página de inicio después del login"""
    # Logging de acceso a inicio
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER ACCESS INICIO - SERVER MSG - SUCCESS',
        nombre_archivo='user_hist.csv',
        tamano=0
    )
    
    return render_template('inicio.html', current_user=current_user)
