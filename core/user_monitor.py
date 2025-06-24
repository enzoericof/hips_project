import subprocess
from utils.logger import log_alarm
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted

def get_logged_users():
    result = subprocess.run(['who'], stdout=subprocess.PIPE, text=True)
    return result.stdout.strip().split('\n')

def analyze_users():
    users = get_logged_users()
    seen = {}
    alerta = False
    detalles = []

    for entry in users:
        parts = entry.split()
        if len(parts) >= 1:
            user = parts[0]
            origin = parts[-1].strip("()") if len(parts) >= 5 else "desconocido"
            detalles.append(f"{user} desde {origin}")
            key = (user, origin)
            if key in seen and not already_alerted("usuarios", str(key)):
                alerta = True
                msg = f"El usuario {user} está conectado desde múltiples orígenes (último: {origin})"
                log_alarm("Usuario duplicado", origin)
                send_email("HIPS - Usuario duplicado", msg)
                mark_alerted("usuarios", str(key))
            else:
                seen[key] = True

    if not detalles:
        return False, "0 usuario(s) únicos con shell activa"
    
    resumen = f"{len(seen)} usuario(s) únicos con shell activa: " + ", ".join(detalles)
    return alerta, resumen
