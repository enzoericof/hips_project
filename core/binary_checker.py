import hashlib
import psycopg2
from utils.logger import log_alarm
from utils.email_alert import send_email

CRITICAL_FILES = [
    "/bin/ls",
    "/bin/bash",
    "/usr/bin/grep",
    "/etc/passwd",
    "/etc/shadow"
]

DB_CONFIG = {
    "dbname": "hips_db",
    "user": "hips_user",
    "password": "hips_secure_pass",
    "host": "localhost"
}

def calcular_sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def obtener_hashes_db():
    hashes = {}
    try:
        con = psycopg2.connect(**DB_CONFIG)
        cur = con.cursor()
        cur.execute("SELECT path, sha256 FROM hips_schema.binary_hashes")
        for path, h in cur.fetchall():
            hashes[path] = h
        cur.close()
        con.close()
    except Exception as e:
        print(f"[ERROR DB lectura] {e}")
    return hashes

def actualizar_hash(path, sha256):
    try:
        con = psycopg2.connect(**DB_CONFIG)
        cur = con.cursor()
        cur.execute("""
            INSERT INTO hips_schema.binary_hashes (path, sha256)
            VALUES (%s, %s)
            ON CONFLICT (path) DO UPDATE SET sha256 = EXCLUDED.sha256
        """, (path, sha256))
        con.commit()
        cur.close()
        con.close()
    except Exception as e:
        print(f"[ERROR DB escritura] {e}")

def monitor_binaries():
    alerta = False
    mensaje = []
    hashes_previos = obtener_hashes_db()

    for archivo in CRITICAL_FILES:
        hash_actual = calcular_sha256(archivo)
        if not hash_actual:
            continue

        hash_esperado = hashes_previos.get(archivo)

        if hash_esperado:
            if hash_actual != hash_esperado:
                log_alarm("Integridad comprometida", archivo)
                send_email("HIPS - Archivo modificado", f"Se detectó un cambio en: {archivo}")
                mensaje.append(f"{archivo} MODIFICADO")
                alerta = True
            else:
                mensaje.append(f"{archivo} OK")
        else:
            mensaje.append(f"{archivo} nuevo, registrado")

        actualizar_hash(archivo, hash_actual)

    return alerta, "\n".join(mensaje)
