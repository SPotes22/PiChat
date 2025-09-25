# src/utils/security.py
from datetime import datetime, timedelta
from typing import Dict, Any

# Estructura global para protección fuerza bruta
_brute_force_data: Dict[str, Dict[str, Any]] = {}

def setup_brute_force_protection(users_dict: Dict[str, Any]):
    """Configurar protección fuerza bruta para usuarios existentes"""
    for username in users_dict:
        if 'failed_attempts' not in users_dict[username]:
            users_dict[username]['failed_attempts'] = 0
        if 'last_attempt' not in users_dict[username]:
            users_dict[username]['last_attempt'] = None

def check_brute_force_protection(username: str, users_dict: Dict[str, Any], 
                               max_attempts: int = 5, lockout_time: int = 900) -> bool:
    """Protección contra fuerza bruta mejorada y modularizada"""
    now = datetime.now()
    
    if username not in users_dict:
        return False  # Usuario no existe
    
    user_data = users_dict[username]
    
    if user_data['failed_attempts'] >= max_attempts:
        if user_data['last_attempt']:
            time_diff = (now - user_data['last_attempt']).total_seconds()
            if time_diff < lockout_time:  # 15 minutos de bloqueo
                return True  # Está bloqueado
            else:
                # Resetear después del tiempo de bloqueo
                reset_failed_attempts(username, users_dict)
    
    return False

def increment_failed_attempt(username: str, users_dict: Dict[str, Any]):
    """Incrementar intentos fallidos"""
    if username in users_dict:
        users_dict[username]['failed_attempts'] += 1
        users_dict[username]['last_attempt'] = datetime.now()

def reset_failed_attempts(username: str, users_dict: Dict[str, Any]):
    """Resetear intentos fallidos después de éxito"""
    if username in users_dict:
        users_dict[username]['failed_attempts'] = 0
        users_dict[username]['last_attempt'] = None
