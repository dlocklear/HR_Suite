import os
from supabase import create_client, Client
from flask import Flask
from flask_bcrypt import Bcrypt
from config import Config
from dotenv import load_dotenv
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

load_dotenv()

bcrypt = Bcrypt()


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

    # Function to send email
    def send_email(to_email, subject, body):
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = int(os.getenv("SMTP_PORT"))
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")
        from_email = os.getenv("SMTP_FROM")

        # Create the email
        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        # Send email
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()  # Secure connection
                server.login(smtp_user, smtp_password)
                server.sendmail(from_email, to_email, msg.as_string())
                print("Email sent successfully")
        except Exception as e:
            print(f"Error sending email: {e}")

    app.send_email = send_email

    from app.routes import init_routes
    init_routes(app)

    return app
