import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from supabase import create_client
from flask import Flask
from flask_bcrypt import Bcrypt
from config import Config

load_dotenv()

bcrypt = Bcrypt()


def send_email(recipient_email, subject, body):
    sender_email = os.getenv("SMTP_SENDER_EMAIL")
    sender_password = os.getenv("SMTP_PASS")
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html'))
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
        logging.info("Email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    bcrypt.init_app(app)

    # Initialize Supabase client and attach to the Flask app
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_ANON_KEY")

    if not url or not key:
        logging.error(
            "Supabase URL or Key not found. Please check the .env file.")
    else:
        logging.info(f"Supabase URL: {url}")
        # Log only the first 10 characters of the key for security
        logging.info(f"Supabase Key: {key[:10]}...")

    app.supabase = create_client(url, key)

    from app.routes import init_routes
    init_routes(app)

    return app
