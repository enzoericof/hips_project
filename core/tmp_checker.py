import os
import re
import shutil
import subprocess
from utils.logger import log_alarm, log_prevention
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted

def move_to_quarantine(filepath):
    quarantine_dir = "/home/kali/hips_project/cuarentena"
    os.makedirs(quarantine_dir, exist_ok=True)
    filename = os.path.basename(filepath)
    dest = os.path.join(quarantine_dir, filename)

    try:
        shutil.copy2(filepath, dest)
        subprocess.run(['sudo', 'rm', '-f', filepath])
    except Exception as e:
        print(f"[ERROR] No se pudo mover a cuarentena: {e}")

def check_tmp_directory():
    tmp_dir = "/tmp"
    alert = False
    mensaje = "Directorio /tmp limpio."

    try:
        for fname in os.listdir(tmp_dir):
            full_path = os.path.join(tmp_dir, fname)
            if not os.path.isfile(full_path):
                continue
            if re.search(r'\.sh|\.py|\.pl|evil|exploit|rev', fname):
                evento_id = f"tmp::{fname}"
                if not already_alerted("tmp", evento_id):
                    alerta_msg = f"Archivo sospechoso detectado en /tmp: {fname}"
                    log_alarm("Archivo sospechoso en /tmp", alerta_msg)
                    send_email("HIPS - Archivo sospechoso en /tmp", alerta_msg)
                    move_to_quarantine(full_path)
                    log_prevention("Archivo movido a cuarentena", alerta_msg)
                    mark_alerted("tmp", evento_id)
                    alert = True
                    mensaje = alerta_msg
    except Exception as e:
        return True, f"Error al analizar /tmp: {e}"

    return alert, mensaje
