from core.file_integrity import check_passwd_changes
from core.user_monitor import analyze_users
from core.sniffer_detection import analyze_sniffers
from core.log_analysis import analyze_logs
from core.tmp_checker import check_tmp_directory
from core.mail_queue import analyze_mail_queue
from core.ddos_detector import detect_ddos
from core.cron_checker import monitor_cron
from core.access_monitor import monitor_failed_logins
from core.binary_checker import monitor_binaries


changed1, msg1 = check_passwd_changes()
print(f"[ALERTA] {msg1}" if changed1 else f"[OK] {msg1}")

changed2, msg2 = analyze_users()
print(f"[ALERTA] {msg2}" if changed2 else f"[OK] {msg2}")

changed3, msg3 = analyze_sniffers()
print(f"[ALERTA] {msg3}" if changed3 else f"[OK] {msg3}")

changed4, msg4 = analyze_logs()
print(f"[ALERTA] {msg4}" if changed4 else f"[OK] {msg4}")

changed5, msg5 = check_tmp_directory()
print(f"[ALERTA] {msg5}" if changed5 else f"[OK] {msg5}")

changed6, msg6 = analyze_mail_queue()
print(f"[ALERTA] {msg6}" if changed6 else f"[OK] {msg6}")

changed8, msg8 = detect_ddos()
print(f"[ALERTA] {msg8}" if changed8 else f"[OK] {msg8}")

changed7, msg7 = monitor_cron()
print(f"[ALERTA] {msg7}" if changed7 else f"[OK] {msg7}")

changed9, msg9 = monitor_failed_logins()
print(f"[ALERTA] {msg9}" if changed9 else f"[OK] {msg9}")

changed10, msg10 = monitor_binaries()
print(f"[ALERTA] {msg10}" if changed10 else f"[OK] {msg10}")
