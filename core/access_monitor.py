import re
from collections import defaultdict
from utils.logger import log_alarm, log_prevention
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted
import subprocess

LOG_PATH = "/var/log/auth.log"  
THRESHOLD = 4  # intentos antes de alertar

def monitor_failed_logins():
    attempts = defaultdict(int)
    alerta = False
    mensaje = "Accesos inválidos dentro del rango permitido."

    try:
        with open(LOG_PATH, "r") as log:
            for line in log:
                # Detecta IPs v4 o v6
                match = re.search(r'Failed password.*from ([\d.:a-fA-F]+)', line)
                if match:
                    ip = match.group(1)
                    attempts[ip] += 1

        for ip, count in attempts.items():
            if ip == "::1":
                continue  # Elegancia: no bloqueamos IPv6 localhost

            if count >= THRESHOLD:
                evento = f"failed_login::{ip}"
                if not already_alerted("accesos_invalidos", evento):
                    mensaje = f"Detectados {count} intentos fallidos desde {ip}"
                    log_alarm("Intentos de acceso fallidos", ip)
                    send_email("HIPS - Múltiples accesos inválidos", mensaje)

                    # Prevención: bloquear IP (solo IPv4)
                    try:
                        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
                        log_prevention("IP bloqueada por intentos fallidos", ip)
                        send_email("HIPS - IP bloqueada", f"Se bloqueó la IP {ip} por múltiples intentos fallidos")
                    except Exception as e:
                        print(f"[ERROR] No se pudo aplicar iptables: {e}")

                    mark_alerted("accesos_invalidos", evento)
                    alerta = True

    except Exception as e:
        return True, f"Error al analizar accesos inválidos: {e}"

    return alerta, mensaje
