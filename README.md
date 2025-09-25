# 🌱 PiChat - Chat Corporativo + Almacenamiento Básico en Red  

[![Status](https://img.shields.io/badge/status-MVP-green)]()  
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()  
[![Flask](https://img.shields.io/badge/flask-2.x-black?logo=flask)]()  
[![Socket.IO](https://img.shields.io/badge/socket.io-Enabled-lightgrey?logo=socketdotio)]()  
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)  

🇨🇴 Proyecto desarrollado por **Santiago Potes Giraldo** – 2025  

---

## 📌 Descripción  

**PiChat** es un sistema ligero de:  
- ✅ **Chat corporativo en red local** con salas privadas y grupales (sin historial).  
- ✅ **MicroNAS**: módulo de almacenamiento básico de archivos en cuarentena.  
- ✅ **Autenticación con roles** (`administrator`, `cliente`, `usuario`).  
- ✅ **Seguridad**: contraseñas hasheadas con **Argon2**.  
- ✅ **Comunicación en tiempo real** vía **Flask-SocketIO**.  

Este software está pensado como un **MVP (Producto Mínimo Viable)** para entornos LAN: oficinas, hogares y laboratorios.  

---

## 🚀 Instalación  

Clona el repo:  
```bash
git clone https://github.com/tuusuario/pichat.git
cd pichat
```
Crea un entorno virtual e instala dependencias:
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
Ejecuta el servidor:

```
python server.py
```
El sistema quedará disponible en:

```
http://127.0.0.1:8080
```
y accesible en red local:

```
http://<TU_IP_LOCAL>:8080
```
🔑 Roles y Accesos

Usuario	Contraseña	Rol
admin	admin123	administrator
cliente	cliente123	cliente
usuario	usuario123	usuario

⚠️ Nota: en producción se recomienda almacenar usuarios en una base de datos y configurar la SECRET_KEY como variable de entorno.

🗂️ Funcionalidad de Archivos

Subir archivos: disponible para admin y cliente.

Descargar archivos: disponible para todos los usuarios autenticados.

Eliminar archivos: restringido a administrator.

Archivos se almacenan en la carpeta ./cuarentena/.

💬 Funcionalidad de Chat

Creación / unión a salas con código + contraseña.

Opción de chat grupal efímero (sin almacenamiento de mensajes).

Eventos de entrada/salida con notificaciones en tiempo real.

Basado en Flask-SocketIO con soporte WebSockets.

🛡️ Seguridad
🔒 Contraseñas con Argon2.

🔑 Sesiones manejadas con Flask-Login.

🚫 Archivos almacenados en "cuarentena" para control previo a ejecución.

⚖️ Código distribuido bajo GPL-3.0-or-later.

📜 Licencia

PiChat - Chat Corporativo Almacenamiento-Básico en Red
Copyright (C) 2025 Santiago Potes Giraldo

This program is free software: you can redistribute it and/or modify it 
under the terms of the GNU General Public License as published by the 
Free Software Foundation, either version 3 of the License, or (at your 
option) any later version.

This program is distributed in the hope that it will be useful, but 
WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

🔗 GPL-3.0 License

🏁 Estado del Proyecto
🚧 MVP listo y funcional.
📌 Próximos pasos:

Persistencia de chats en DB (SQLite/Postgres).

Escaneo antivirus de archivos subidos.

Panel de administración para gestión de usuarios.

Dockerización para despliegue rápido.

💡 PiChat es un paso hacia un NAS + sistema de chat privado, simple y seguro para redes locales.

Version OWASP:
para mitigar fallos de arquitectura se opto por una solucion hibrida de modularidad. rutas no criticas en app.py

resumen: 
🎯 ¿POR QUÉ ESTO SÍ FUNCIONA?
✅ No hay importaciones circulares - Las rutas están en app.py

✅ Limiter se inicializa UNA vez al principio

✅ Usamos los módulos que SÍ funcionan (seguridad, sanitización)

✅ Mantenemos la lógica compleja modularizada

✅ Las rutas simples quedan en app.py
Detalles de implementacion:
## 🔒 CUMPLIMIENTO OWASP TOP 10 2021

### ✅ Protecciones Implementadas Según Estándares OWASP

#### **A01:2021 - Broken Access Control**
- ✅ Control de roles y permisos (admin, cliente, usuario)
- ✅ Protección de rutas con `@login_required`
- ✅ Validación de ownership en descargas/eliminaciones
- ✅ Rate limiting por tipo de usuario

#### **A02:2021 - Cryptographic Failures**
- ✅ Hashing con **Argon2** (industry standard)
- ✅ Contraseñas nunca en texto plano
- ✅ Claves secretas desde variables de entorno
- ✅ Cookies seguras con flags `HttpOnly`, `Secure`, `SameSite`

#### **A03:2021 - Injection**
- ✅ Sanitización centralizada de inputs
- ✅ Prepared statements para logs (CSV seguro)
- ✅ Validación de tipos y longitud
- ✅ Escape de caracteres especiales en mensajes

#### **A05:2021 - Security Misconfiguration**
- ✅ Configuración segura por defecto
- ✅ Headers CORS restrictivos
- ✅ Logging de auditoría comprehensivo
- ✅ Entornos separados (dev/prod)

#### **A06:2021 - Vulnerable and Outdated Components**
- ✅ Dependencias actualizadas y auditadas
- ✅ Monitoreo de vulnerabilidades conocido
- ✅ Stack tecnológico moderno y mantenido

#### **A07:2021 - Identification and Authentication Failures**
- ✅ Protección contra fuerza bruta (máx 5 intentos, bloqueo 15min)
- ✅ Mecanismos de autenticación seguros
- ✅ Gestión segura de sesiones
- ✅ Logout completo y seguro

### 🛡️ **Características de Seguridad Adicionales**

#### **Protección Contra DoS**

```python
# Rate limiting por IP y usuario
limiter = Limiter(default_limits=["200 per day", "50 per hour"])
@limiter.limit("5 per minute")  # Subida archivos
@limiter.limit("10 per minute") # Descargas
@limiter.limit("3 per minute")  # Eliminación
```

## Seguridad en Tiempo Real (WebSockets)
✅ Autenticación SocketIO con middleware

✅ Rate limiting por conexión WebSocket

✅ Sanitización de mensajes en tiempo real

✅ Validación de salas con Argon2

## Auditoría y Logging

```
python
# Logger concurrente con buffer
logger = AdvancedLogger(
    logs_dir='./logs',
    max_file_size_mb=10,
    buffer_size=100  # Optimizado para alta carga
)
```

## Protección de Archivos
✅ Sanitización de nombres con secure_filename()

✅ Cuarentena de archivos subidos

✅ Validación de tipos MIME implícita

✅ Límite de tamaño (16MB por archivo)


📊 Métricas de Seguridad

Categoría	Nivel de Protección	Implementación
Autenticación	🔒🔒🔒🔒🔒	Argon2 + Fuerza Bruta
Autorización	🔒🔒🔒🔒🔒	RBAC + Middleware
Validación Input	🔒🔒🔒🔒○	Sanitización centralizada
Protección DoS	🔒🔒🔒🔒○	Rate Limiting multi-nivel
Auditoría	🔒🔒🔒🔒🔒	Logger con buffer y rotación
## 🚀 Hardening Adicional

```
bash
# Variables de entorno críticas
SECRET_KEY=tu_clave_super_secreta_aqui
ADMIN_PASS=contraseña_compleja_admin
ALLOWED_ORIGINS=https://tudominio.com
DEBUG=False  # En producción
```


