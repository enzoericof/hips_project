from flask import Flask, render_template, request, redirect, session, url_for
import os
import sys
import psycopg2
import bcrypt

DB_CONFIG = {
    "dbname": "hips_db",
    "user": "hips_user",
    "host": "localhost"
}

# Agregamos la ruta del proyecto para importar los módulos
sys.path.append("/home/kali/hips_project")

# Funciones importadas de cada archivo Python
from core.process_monitor import monitor_memory
from core.log_analysis import analyze_logs
from core.tmp_checker import check_tmp_directory
from core.cron_checker import monitor_cron
from core.sniffer_detection import analyze_sniffers
from core.ddos_detector import detect_ddos
from core.user_monitor import analyze_users as monitor_users
from core.access_monitor import monitor_failed_logins
from core.binary_checker import monitor_binaries
from core.mail_queue import analyze_mail_queue

# Web y algunas rutas
app = Flask(__name__)
app.secret_key = 'seguridad_hips_2025'
LOG_ALERTAS = '/var/log/hips/alarmas.log'
LOG_PREVENCION = '/var/log/hips/prevencion.log'

# Funciones
@app.route('/', methods=['GET'])
def index():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    return render_dashboard()

@app.route('/run', methods=['POST'])
def ejecutar_modulo():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    modulo = request.form.get('modulo')
    resultado = "[ERROR] Módulo desconocido"

    try:
        if modulo == 'memory':
            _, resultado = monitor_memory()
        elif modulo == 'logs':
            _, resultado = analyze_logs()
        elif modulo == 'tmp':
            _, resultado = check_tmp_directory()
        elif modulo == 'cron':
            _, resultado = monitor_cron()
        elif modulo == 'sniffer':
            _, resultado = analyze_sniffers()
        elif modulo == 'mails':
            _, resultado = analyze_mail_queue()
        elif modulo == 'ddos':
            _, resultado = detect_ddos()
        elif modulo == 'users':
            _, resultado = monitor_users()
        elif modulo == 'access':
            _, resultado = monitor_failed_logins()
        elif modulo == 'binaries':
            _, resultado = monitor_binaries()
        elif modulo == 'fullscan':
            r = []
            try:
                orden = [
                    ("🔧 Binarios críticos", monitor_binaries),
                    ("👤 Usuarios", monitor_users),
                    ("🕵 Sniffers", analyze_sniffers),
                    ("📄 Analizar logs", analyze_logs),
                    ("📥 Verificar Cola de Mails", analyze_mail_queue),
                    ("🔍 Monitor de RAM", monitor_memory),
                    ("🧼 Escaneo de /tmp", check_tmp_directory),
                    ("🌐 DDoS", detect_ddos),
                    ("📅 Tareas cron", monitor_cron),
                    ("🔐 Accesos inválidos", monitor_failed_logins)
                ]
                for etiqueta, funcion in orden:
                    _, msg = funcion()
                    r.append(f"{etiqueta}:\n{msg.strip()}\n")
                resultado = "\n".join(r)
            except Exception as e:
                 resultado = f"[ERROR en fullscan] {e}"
    except Exception as e:
        resultado = f"[ERROR] {e}"

    return render_dashboard(resultado)

def render_dashboard(resultado=None):
    alertas = []
    prevencion = []
    if os.path.exists(LOG_ALERTAS):
        with open(LOG_ALERTAS) as f:
            alertas = list(reversed(f.readlines()))

    if os.path.exists(LOG_PREVENCION):
        with open(LOG_PREVENCION) as f:
            prevencion = list(reversed(f.readlines()))

    return render_template('dashboard.html', alertas=alertas, prevencion=prevencion, resultado=resultado)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = request.form['usuario']
        pwd = request.form['clave']

        try:
            con = psycopg2.connect(**DB_CONFIG)
            cur = con.cursor()
            cur.execute("SELECT password FROM hips_schema.gui_credentials WHERE username = %s", (user,))
            result = cur.fetchone()
            cur.close()
            con.close()

            if result and bcrypt.checkpw(pwd.encode(), result[0].encode()):
                session['usuario'] = user
                return redirect('/')
            else:
                error = "Credenciales incorrectas"
        except Exception as e:
            error = f"Error de conexión a la base de datos: {e}"

    return render_template("login.html", error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

import subprocess

@app.route('/terminal', methods=['GET', 'POST'])
def terminal():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    salida = ''
    comando = ''

    if request.method == 'POST':
        comando = request.form.get('comando')
        try:
            # Forzamos bash como si fuera una terminal real
            resultado = subprocess.run(['bash', '-c', comando], capture_output=True, text=True)
            salida = resultado.stdout + resultado.stderr
        except Exception as e:
            salida = f"[ERROR] {e}"

    return render_template('terminal.html', salida=salida, comando=comando)

from flask import send_file

@app.route('/download/<logtype>')
def download_log(logtype):
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if logtype == "alarmas":
        return send_file("/var/log/hips/alarmas.log", as_attachment=True)
    elif logtype == "prevencion":
        return send_file("/var/log/hips/prevencion.log", as_attachment=True)
    else:
        return "[ERROR] Log no válido"

if __name__ == '__main__':
    app.run(debug=True, port=8080)
