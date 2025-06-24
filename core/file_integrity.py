import hashlib
from utils.logger import log_alarm
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted

def hash_file(filepath):
    with open(filepath, 'rb') as f:
        content = f.read()
    return hashlib.sha256(content).hexdigest()

def check_passwd_changes(reference_hash_file='/home/kali/hips_project/config/passwd_hash.txt'):
    passwd_path = '/etc/passwd'
    current_hash = hash_file(passwd_path)

    try:
        with open(reference_hash_file, 'r') as f:
            old_hash = f.read().strip()
    except FileNotFoundError:
        with open(reference_hash_file, 'w') as f:
            f.write(current_hash)
        return False, "Referencia creada."

    if current_hash != old_hash:
        if not already_alerted("integridad", "passwd"):
            msg = "Modificación detectada en /etc/passwd"
            log_alarm("MODIFICACIÓN /etc/passwd")
            send_email("HIPS - Alarma detectada", msg)
            mark_alerted("integridad", "passwd")
        return True, "Modificación detectada en /etc/passwd"

    return False, "Sin cambios."

