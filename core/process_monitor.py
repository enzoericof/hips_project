import psutil
from utils.logger import log_alarm, log_prevention
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted

def monitor_memory(threshold_percent=5):
    alert = False
    mensajes = []

    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        try:
            mem = proc.info['memory_percent']
            if mem and mem > threshold_percent:
                alert = True
                nombre = proc.info['name']
                pid = proc.info['pid']
                msg = f"Proceso {nombre} (PID {pid}) usa {mem:.2f}% de RAM"

                log_alarm("Proceso con alto uso de RAM", nombre)
                if not already_alerted("ram", str(pid)):
                    send_email("HIPS - RAM Alta", msg)
                    mark_alerted("ram", str(pid))

                # Acción de prevención (ej: matar proceso)
                try:
                    p = psutil.Process(pid)
                    p.kill()
                    log_prevention("Proceso eliminado por RAM", nombre)
                except Exception as e:
                    mensajes.append(f"[ERROR] No se pudo matar {nombre}: {e}")
                mensajes.append(msg)
        except Exception:
            continue

    return alert, "\n".join(mensajes) if alert else "[OK] Consumo de memoria dentro de límites."

