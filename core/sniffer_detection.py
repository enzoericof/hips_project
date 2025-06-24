import os
import subprocess
from utils.logger import log_alarm, log_prevention
from utils.email_alert import send_email
from utils.estado import already_alerted, mark_alerted

SNIFFER_PROCESSES = ['tcpdump', 'wireshark', 'tshark', 'ettercap', 'dsniff']

def detect_promiscuous_interfaces():
    promisc_ifaces = []
    for iface in os.listdir('/sys/class/net/'):
        try:
            with open(f'/sys/class/net/{iface}/flags', 'r') as f:
                flags = int(f.read().strip(), 16)
                if flags & 0x100:
                    promisc_ifaces.append(iface)
        except Exception:
            continue
    return promisc_ifaces

def detect_sniffer_processes():
    found = []
    try:
        result = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            for proc in SNIFFER_PROCESSES:
                if proc in line:
                    found.append(proc)
    except Exception as e:
        print(f"[ERROR] No se pudo analizar procesos: {e}")
    return list(set(found))

def take_preventive_actions(processes):
    for proc in processes:
        try:
            result = subprocess.run(['pgrep', '-f', proc], stdout=subprocess.PIPE, text=True)
            pids = result.stdout.strip().split('\n')
            for pid in pids:
                if pid.isdigit():
                    subprocess.run(['kill', '-9', pid])
                    log_prevention(f"Proceso de sniffer eliminado: {proc} (PID {pid})")
                    send_email("HIPS - Prevención aplicada", f"Se eliminó el proceso sospechoso: {proc} (PID {pid})")
        except Exception as e:
            print(f"[ERROR] No se pudo eliminar {proc}: {e}")

def analyze_sniffers():
    alerta = False

    promisc = detect_promiscuous_interfaces()
    if promisc:
        for iface in promisc:
            log_alarm("Modo promiscuo detectado", iface)
            if not already_alerted("promiscuo", iface):
                send_email("HIPS - Modo promiscuo", f"La interfaz {iface} está en modo promiscuo")
                mark_alerted("promiscuo", iface)
                alerta = True

    sniffers = detect_sniffer_processes()
    if sniffers:
        for proc in sniffers:
            log_alarm("Sniffer detectado", proc)
            if not already_alerted("sniffer", proc):
                mark_alerted("sniffer", proc)
                alerta = True
        take_preventive_actions(sniffers)

    return alerta, "Modo promiscuo o sniffers detectados" if alerta else "Todo limpio"

