import os
import re
from utils.logger import log_alarm, log_prevention
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted

def monitor_cron():
    cron_dir = "/var/spool/cron/crontabs/"
    alert = False
    mensaje = "Tareas cron dentro de lo normal."

    if not os.path.exists(cron_dir):
        return False, "No existe el directorio de cron."

    for user_file in os.listdir(cron_dir):
        path = os.path.join(cron_dir, user_file)
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if not line.strip() or line.startswith('#'):
                        continue
                    if re.search(r'(wget|curl|/tmp/|/dev/shm/|python|nc|bash)', line):
                        evento_id = f"cron::{user_file}::{line.strip()}"
                        if not already_alerted("cron", evento_id):
                            alerta_msg = f"Tarea cron sospechosa para usuario {user_file}: {line.strip()}"
                            log_alarm("Tarea cron sospechosa", alerta_msg)
                            send_email("HIPS - Cron sospechoso", alerta_msg)
                            log_prevention("Tarea cron marcada como peligrosa", alerta_msg)
                            mark_alerted("cron", evento_id)
                            alert = True
                            mensaje = alerta_msg
        except Exception as e:
            return True, f"Error leyendo crontab de {user_file}: {e}"

    return alert, mensaje
