import os
from utils.logger import log_alarm, log_prevention
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted

MAIL_DIRS = ["/var/spool/postfix/deferred", "/var/spool/postfix/maildrop"]

def analyze_mail_queue(threshold=10):
    total = 0
    for path in MAIL_DIRS:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                total += len(files)

    if total >= threshold:
        log_alarm("Cola de correo elevada", f"{total} mensajes")
        if not already_alerted("cola_mail", "sistema"):
            send_email("HIPS - Cola de correo", f"Se detectaron {total} mensajes en la cola de correo.")
            mark_alerted("cola_mail", "sistema")
        return True, f"[ALERTA] Cola de correos: {total} mensajes"
    else:
        return False, "[OK] Cola de correo dentro de límites"
