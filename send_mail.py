import smtplib
import ssl
import os
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage


load_dotenv()

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
FROM_NAME = os.getenv("EMAIL_FROM_NAME")


def parse_emails(env_var):
    if not env_var:
        return []

    return [
        email.strip().replace("\n", "").replace("\r", "")
        for email in env_var.split(",")
        if email.strip()
    ]


def send_email(email_body):

    msg = MIMEMultipart("related")
    msg["From"] = FROM_NAME
    msg["Subject"] = "Relatório de Vulnerabilidades Novas"

    to_list = parse_emails(os.getenv("EMAIL_TO"))
    cc_list = parse_emails(os.getenv("EMAIL_CC"))

    if to_list:
        msg["To"] = ", ".join(to_list)

    if cc_list:
        msg["Cc"] = ", ".join(cc_list)

    recipients = list(set(to_list + cc_list))

    # Parte alternativa (HTML + texto)
    msg_alternative = MIMEMultipart("alternative")
    msg.attach(msg_alternative)

    msg_text = MIMEText("Seu cliente de email não suporta HTML.", "plain")
    msg_alternative.attach(msg_text)

    msg_html = MIMEText(email_body, "html")
    msg_alternative.attach(msg_html)

    # Caminho absoluto do logo
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(BASE_DIR, "img", "brainwalk.png")

    try:
        with open(logo_path, "rb") as img_file:
            logo = MIMEImage(img_file.read())
            logo.add_header("Content-ID", "<logo_cid>")
            logo.add_header("Content-Disposition", "inline", filename="brainwalk.png")
            msg.attach(logo)
    except FileNotFoundError:
        print("Logo não encontrado em:", logo_path)

    try:
        context = ssl.create_default_context()

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, recipients, msg.as_string())

        print(f"Email enviado para: {recipients}")

    except Exception as e:
        print("Erro ao enviar e-mail:", e)