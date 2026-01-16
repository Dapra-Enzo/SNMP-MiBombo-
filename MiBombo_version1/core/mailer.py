
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading

# Configuration SMTP (Gmail)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
ADMIN_EMAIL = "dapraenzo1gmail.com"  # Note: user wrote "dapraenzo1gmail.com", assuming "dapraenzo1@gmail.com" or literally that? 
# "dapraenzo1gmail.com" is invalid email. Likely "dapraenzo1@gmail.com". I will use the corrected one but print a warning.
# Actually, I will interpret it as "dapraenzo1@gmail.com" based on common typos.
ADMIN_EMAIL_CORRECTED = "dapraenzo1@gmail.com"
SMTP_PASSWORD = "drsj jvji gphp beql"

def send_email_async(subject, body, to_email):
    """Envoie un email en arrière-plan."""
    def _send():
        try:
            msg = MIMEMultipart()
            msg['From'] = ADMIN_EMAIL_CORRECTED
            msg['To'] = to_email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(ADMIN_EMAIL_CORRECTED, SMTP_PASSWORD)
            text = msg.as_string()
            server.sendmail(ADMIN_EMAIL_CORRECTED, to_email, text)
            server.quit()
            print(f"[+] Email envoyé à {to_email}")
        except Exception as e:
            print(f"[!] Erreur envoi email: {e}")

    threading.Thread(target=_send).start()

def notify_admin_new_user(username, email):
    """Notifie l'admin d'une nouvelle inscription."""
    subject = f"MiBombo - Nouvelle inscription : {username}"
    body = f"""
Bonjour Admin,

Un nouvel utilisateur s'est inscrit sur MiBombo Station.

Nom d'utilisateur : {username}
Email : {email}

Veuillez vous connecter à l'interface d'administration pour activer ce compte s'il est légitime.

Cordialement,
MiBombo Security System
    """
    send_email_async(subject, body, ADMIN_EMAIL_CORRECTED)

def notify_user_pending(email, username):
    """Notifie l'utilisateur que son compte est en attente."""
    subject = "MiBombo - Inscription enregistrée"
    body = f"""
Bonjour {username},

Votre demande d'inscription a bien été prise en compte.
Un administrateur doit valider votre compte avant que vous puissiez vous connecter.

Vous recevrez une notification une fois votre compte activé.

Cordialement,
MiBombo Security System
    """
    send_email_async(subject, body, email)
