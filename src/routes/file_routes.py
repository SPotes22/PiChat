# src/routes/file_routes.py
import os
from flask import Blueprint, request, render_template, redirect, url_for, send_from_directory
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from src.utils.input_sanitizer import sanitize_filename
from src.services.logger_service import AdvancedLogger

file_bp = Blueprint('file', __name__, url_prefix='/archivos')

# Dependencias a inicializar
UPLOAD_FOLDER = ''
logger = None
limiter = None

def init_file_routes(upload_folder, logger_instance, limiter_instance):
    """Inicializar dependencias de las rutas de archivos"""
    global UPLOAD_FOLDER, logger, limiter
    UPLOAD_FOLDER = upload_folder
    logger = logger_instance
    limiter = limiter_instance

@file_bp.route('/subir', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute")
def subir():
    """Subir archivos con verificación de permisos"""
    if current_user.rol == 'usuario':
        return 'No tienes permiso para subir archivos', 403
    
    if request.method == 'POST':
        if 'archivo' not in request.files:
            return 'No se encontró el archivo', 400
        
        archivo = request.files['archivo']
        if archivo.filename == '':
            return 'No se seleccionó ningún archivo', 400
        
        # Sanitizar nombre del archivo
        filename = sanitize_filename(archivo.filename)
        safe_filename = secure_filename(filename)
        
        file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
        archivo.save(file_path)

        # Logging de archivo subido
        logger.log_archivo(
            usuario=current_user.id,
            accion='subir',
            nombre_archivo=safe_filename,
            tamano=archivo.content_length
        )
        return redirect(url_for('file.listar'))
    
    return render_template("subir.html")

@file_bp.route('/listar')
@login_required
def listar():
    """Listar archivos disponibles"""
    try:
        archivos = os.listdir(UPLOAD_FOLDER)
        
        # Logging de listado de archivos
        logger.log_archivo(
            usuario=current_user.id,
            accion='USER LISTS FILES FROM SERVER - SUCCESS',
            nombre_archivo='file_list',
            tamano=len(archivos)
        )
        
        return render_template("listar.html", archivos=archivos)
    except Exception as e:
        logger.log_archivo(
            usuario=current_user.id,
            accion='ERROR_LISTING_FILES',
            nombre_archivo='error',
            tamano=0
        )
        return f"Error al listar archivos: {str(e)}", 500

@file_bp.route('/descargar/<nombre>')
@login_required
@limiter.limit("10 per minute")
def descargar(nombre):
    """Descargar archivo con verificación de seguridad"""
    # Sanitizar nombre del archivo
    safe_filename = sanitize_filename(nombre)
    
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    
    if not os.path.exists(file_path):
        return 'Archivo no encontrado', 404
    
    file_size = os.path.getsize(file_path)

    # Logging de descarga
    logger.log_archivo(
        usuario=current_user.id,
        accion='USER DOWNLOADS FILE - SUCCESS',
        nombre_archivo=safe_filename,
        tamano=file_size
    )
    
    return send_from_directory(UPLOAD_FOLDER, safe_filename, as_attachment=True)

@file_bp.route('/eliminar/<nombre>')
@login_required
@limiter.limit("3 per minute")
def eliminar(nombre):
    """Eliminar archivo (solo administradores)"""
    if current_user.rol != 'administrator':
        return 'No tienes permiso para eliminar archivos', 403
    
    # Sanitizar nombre del archivo
    safe_filename = sanitize_filename(nombre)
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    
    try:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            os.remove(file_path)

            # Logging de eliminación
            logger.log_archivo(
                usuario=current_user.id,
                accion='ARCHIVO ELIMINADO - SUCCESS',
                nombre_archivo=safe_filename,
                tamano=file_size
            )
        else:
            return 'Archivo no encontrado', 404
            
    except Exception as e:
        logger.log_archivo(
            usuario=current_user.id,
            accion='ERROR_DELETING_FILE',
            nombre_archivo=safe_filename,
            tamano=-1
        )
        return f"Error al eliminar archivo: {str(e)}", 500
    
    return redirect(url_for('file.listar'))
