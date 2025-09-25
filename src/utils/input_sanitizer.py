# src/utils/input_sanitizer.py
import re
from werkzeug.utils import secure_filename

def sanitize_input(text: str, max_length: int = 1000, allowed_chars: str = None) -> str:
    """Sanitización básica de input con límite de longitud"""
    if not text:
        return ""
    
    # Limitar longitud
    text = text[:max_length]
    
    # Eliminar caracteres potencialmente peligrosos si no se especifican allowed_chars
    if allowed_chars is None:
        # Permitir caracteres alfanuméricos básicos y algunos especiales comunes
        text = re.sub(r'[^\w\s@\.\-_!?¿¡áéíóúñÁÉÍÓÚÑ]', '', text)
    
    # Prevenir XSS básico
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    text = text.replace('"', '&quot;').replace("'", '&#x27;')
    
    return text.strip()

def sanitize_filename(filename: str) -> str:
    """Sanitización especializada para nombres de archivo"""
    if not filename:
        return "unnamed_file"
    
    # Usar werkzeug's secure_filename como base
    safe_name = secure_filename(filename)
    
    # Limitar longitud adicional
    safe_name = safe_name[:255]
    
    return safe_name

def sanitize_message(message: str, max_length: int = 1000) -> str:
    """Sanitización especializada para mensajes de chat"""
    if not message:
        return ""
    
    # Limitar longitud
    message = message[:max_length]
    
    # Sanitización básica pero permitiendo más caracteres para mensajes
    message = message.replace('<', '&lt;').replace('>', '&gt;')
    
    # Permitir saltos de línea pero sanitizarlos
    message = message.replace('\n', '<br>').replace('\r', '')
    
    return message.strip()

def sanitize_room_code(room_code: str, max_length: int = 20) -> str:
    """Sanitización especializada para códigos de sala"""
    if not room_code:
        return "default"
    
    # Limitar longitud
    room_code = room_code[:max_length]
    
    # Solo caracteres alfanuméricos y guiones
    room_code = re.sub(r'[^\w\-]', '', room_code)
    
    return room_code
