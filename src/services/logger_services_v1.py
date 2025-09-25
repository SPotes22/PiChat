# src/services/logger_service.py
import csv
import os
from datetime import datetime
from threading import Lock

class AdvancedLogger:
    def __init__(self, logs_dir='./logs', max_file_size_mb=10):
        self.logs_dir = logs_dir
        self.max_file_size = max_file_size_mb * 1024 * 1024  # Convertir a bytes
        self.lock = Lock()  # Para manejar concurrencia
        
        # Crear directorio de logs si no existe
        os.makedirs(logs_dir, exist_ok=True)
    
    def _get_current_log_path(self, log_type: str) -> str:
        """Genera ruta de log con fecha actual"""
        date_str = datetime.now().strftime('%Y%m%d')
        return os.path.join(self.logs_dir, f'{log_type}_{date_str}.csv')
    
    def _needs_rotation(self, file_path: str) -> bool:
        """Verifica si el archivo necesita rotación por tamaño"""
        if not os.path.exists(file_path):
            return False
        return os.path.getsize(file_path) >= self.max_file_size
    
    def _rotate_log(self, log_type: str):
        """Rota el log actual agregando timestamp"""
        current_path = self._get_current_log_path(log_type)
        if os.path.exists(current_path):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archived_path = os.path.join(self.logs_dir, f'archive/{log_type}_{timestamp}.csv')
            os.makedirs(os.path.dirname(archived_path), exist_ok=True)
            os.rename(current_path, archived_path)
    
    def log_event(self, log_type: str, headers: list, data: list):
        """Versión mejorada de tu función con rotación y append"""
        
        with self.lock:  # Previene condiciones de carrera
            log_path = self._get_current_log_path(log_type)
            
            # Rotar si es necesario
            if self._needs_rotation(log_path):
                self._rotate_log(log_type)
                log_path = self._get_current_log_path(log_type)  # Nueva ruta
            
            # Verificar si el archivo existe para escribir headers
            file_exists = os.path.exists(log_path)
            
            try:
                with open(log_path, mode='a', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    
                    # Escribir headers solo si el archivo es nuevo
                    if not file_exists:
                        writer.writerow(headers + ['timestamp'])
                    
                    # Escribir datos con timestamp
                    writer.writerow(data + [datetime.now().isoformat()])
                
                print(f"[{datetime.now()}] Log entry added to {log_path}")
                return True
                
            except Exception as e:
                print(f"[ERROR] Could not write to log: {e}")
                return False

    # Tus funciones específicas para chat y archivos
    def log_archivo(self, usuario: str, accion: str, nombre_archivo: str, tamano: int = None):
        headers = ['usuario', 'accion', 'archivo', 'tamano_bytes']
        data = [usuario, accion, nombre_archivo, tamano or 0]
        return self.log_event('archivos', headers, data)
    
    def log_chat(self, usuario: str, accion: str, sala: str, tamano_mensaje: int = None):
        headers = ['usuario', 'accion', 'sala', 'tamano_mensaje_bytes']
        data = [usuario, accion, sala, tamano_mensaje or 0]
        return self.log_event('chat', headers, data)

# Manteniendo tu función original para compatibilidad
def generar_log(path: str, headers: list, rows: list[list]):
    """TU FUNCIÓN ORIGINAL - se mantiene para backward compatibility"""
    try:
        with open(path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(rows)
        print(f"[{datetime.now()}] Log successfully created at {path}")
        return True
    except Exception as e:
        print(f"[ERROR] Could not generate log: {e}")
        return False
