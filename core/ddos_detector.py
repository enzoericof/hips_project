import os
import re
from collections import defaultdict
from utils.logger import log_alarm, log_prevention
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted
import subprocess

LOG_PATH = "/var/log/hips/ddos.log"
THRESHOLD = 5

def block_ip(ip):
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
        log_prevention("IP bloqueada (DDoS)", ip)
        send_email("HIPS - IP bloqueada por DDoS", f"La IP {ip} fue bloqueada por exceso de peticiones DNS.")
    except Exception as e:
        print(f"[ERROR] No se pudo bloquear {ip}: {e}")

def detect_ddos():
    if not os.path.exists(LOG_PATH):
        return False, "[OK] No se encontró el log de DDoS"

    counter = defaultdict(int)
    with open(LOG_PATH, "r") as f:
        for line in f:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                counter[ip] += 1

    alert = False
    sospechosos = []

    for ip, count in counter.items():
        if count >= THRESHOLD and not already_alerted("ddos", ip):
            alert = True
            log_alarm("DDoS detectado", ip)
            block_ip(ip)
            mark_alerted("ddos", ip)
            sospechosos.append(ip)

    return alert, f"[ALERTA] IPs sospechosas: {sospechosos}" if alert else "[OK] Sin actividad sospechosa"

