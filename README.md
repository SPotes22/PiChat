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
http://127.0.0.1:8000
```
y accesible en red local:

```
http://<TU_IP_LOCAL>:8000
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
