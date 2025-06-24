from datetime import datetime

ALARM_LOG = '/var/log/hips/alarmas.log'
PREVENTION_LOG = '/var/log/hips/prevencion.log'

def log_alarm(alarm_type, ip='N/A'):
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    with open(ALARM_LOG, 'a') as f:
        f.write(f"{timestamp} :: {alarm_type} :: {ip}\n")

def log_prevention(action_type, ip='N/A'):
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    with open(PREVENTION_LOG, 'a') as f:
        f.write(f"{timestamp} :: {action_type} :: {ip}\n")
