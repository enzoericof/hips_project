import re
from collections import defaultdict
from utils.logger import log_alarm, log_prevention
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted
import subprocess
import os

LOG_FILES = {
    "auth": ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"],
    "http": ["/var/log/httpd/access.log"],
    "mail": ["/var/log/maillog"]
}

def block_ip(ip):
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
        log_prevention("IP bloqueada", ip)
        send_email("HIPS - IP bloqueada por logs", f"La IP {ip} fue bloqueada por actividad sospechosa en logs.")
    except Exception as e:
        print(f"[ERROR] No se pudo bloquear la IP {ip}: {e}")

def analyze_logs():
    ip_counter = defaultdict(int)

    # Fallos de autenticación
    for logfile in LOG_FILES["auth"]:
        if os.path.exists(logfile):
            with open(logfile, 'r') as f:
                lines = f.readlines()[-100:]
                for line in lines:
                    if "Failed password" in line or "authentication failure" in line.lower():
                        match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            ip = match.group(1)
                            ip_counter[ip] += 1

    # Errores HTTP
    for logfile in LOG_FILES["http"]:
        if os.path.exists(logfile):
            with open(logfile, 'r') as f:
                lines = f.readlines()[-100:]
                for line in lines:
                    if " 404 " in line:
                        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            ip = match.group(1)
                            ip_counter[ip] += 1

    # Actividad de mail
    for logfile in LOG_FILES["mail"]:
        if os.path.exists(logfile):
            with open(logfile, 'r') as f:
                lines = f.readlines()[-100:]
                for line in lines:
                    if "from=<" in line:
                        match = re.search(r'from=<([^>]+)>', line)
                        if match:
                            user = match.group(1)
                            ip_counter[user] += 1

    alert = False
    sospechosos = []

    for item, count in ip_counter.items():
        if count >= 4:
            sospechosos.append(item)
            if not already_alerted("log", item):
                log_alarm("Patrón sospechoso detectado", item)
                send_email("HIPS - Patrón sospechoso", f"{item} con {count} repeticiones en logs.")
                if re.match(r'\d+\.\d+\.\d+\.\d+', item) and item != "127.0.0.1":
                    block_ip(item)
                mark_alerted("log", item)
            alert = True

    return alert, f"Análisis de logs completado. Elementos sospechosos: {sospechosos}" if alert else "[OK] Sin hallazgos graves."

