import smtplib
from email.message import EmailMessage

# DATOS DEL REMITENTE
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_ADDRESS = 'enzoericof@gmail.com'
EMAIL_PASSWORD = 'driq hujw rztd yjpy'

def send_email(subject, body, to='enzoericof@gmail.com'):
    msg = EmailMessage()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"[OK] Correo enviado a {to}")
    except Exception as e:
        print(f"[ERROR] No se pudo enviar el correo: {e}")

