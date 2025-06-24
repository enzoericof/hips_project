# 🛡️ HIPS Project - Host-based Intrusion Prevention System

Este es un sistema HIPS desarrollado como parte del trabajo práctico de Sistemas Operativos. Detecta y previene comportamientos sospechosos en una estación de trabajo o servidor Linux (Kali / CentOS).

---

## 🚀 Funcionalidades implementadas

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | **Verificación de binarios** | Detecta cambios en `/bin/ls`, `/bin/bash`, `/etc/passwd`, `/etc/shadow`, etc. |
| 2 | **Usuarios activos** | Monitorea usuarios conectados y sus orígenes. |
| 3 | **Sniffer y modo promiscuo** | Detecta y bloquea sniffers como `tcpdump`, `wireshark`, etc. |
| 4 | **Análisis de logs** | Detecta ataques desde `/var/log/auth.log`, `/var/log/httpd/access.log`, y `/var/log/maillog`. |
| 5 | **Cola de mails** | Verifica el tamaño de la cola de `postfix`. |
| 6 | **Uso excesivo de RAM** | Identifica y mata procesos que consumen demasiada memoria. |
| 7 | **Directorio `/tmp`** | Detecta scripts sospechosos y los mueve a cuarentena. |
| 8 | **DDoS** | Detecta y bloquea IPs con comportamiento de ataque por logs simulados. |
| 9 | **Cron** | Detecta tareas cron inusuales ejecutadas por usuarios. |
| 10 | **Accesos inválidos** | Detecta múltiples accesos fallidos por usuario o IP. |

---

## 🧪 Pruebas

El sistema incluye funciones para simular:
- Envío masivo de mails
- Ataques por fuerza bruta
- Sniffers activos
- Scripts en `/tmp`
- Carga de RAM excesiva

---

## 🕸️ Interfaz Web

Incluye una GUI desarrollada en Flask que permite:
- Ejecutar escaneos individuales o completos
- Visualizar alertas (`alarmas.log`) y acciones de prevención (`prevencion.log`)
- Acceder con usuario/contraseña cifrada
- Ejecutar comandos desde una terminal interna

---

## 🔐 Seguridad y PostgreSQL

- Contraseñas y hashes protegidos con bcrypt
- Parámetros sensibles ocultos con `.pgpass` y `db_secrets`
- Al menos **10 políticas CIS aplicadas a PostgreSQL**
- Logs del sistema en `/var/log/hips`

---

## 🧰 Requisitos

- Python 3.10+
- PostgreSQL 17+
- `pip install -r requirements.txt` (con entorno virtual recomendado)

---

## 📂 Estructura del proyecto

hips_project/
├── core/ # Lógica de detección y prevención
├── utils/ # Logger, envío de correo, firewall
├── web/ # Interfaz Flask
├── cuarentena/ # Archivos sospechosos movidos
├── main.py # Escaneo completo desde terminal
└── README.md


---

## 👨‍💻 Autor

Desarrollado por [Enzo Erico](https://github.com/enzoericof) - 2025

---

## 📜 Licencia

Uso académico y educativo.
