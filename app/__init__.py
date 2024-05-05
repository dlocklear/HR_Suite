from sendgrid.helpers.mail import Mail
from sendgrid import SendGridAPIClient
import os
from supabase import create_client, Client
from flask import Flask
from dotenv import load_dotenv
load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_ANON_KEY")

    if not url or not key:
        raise EnvironmentError(
            "Missing Supabase configuration in environment variables.")

    # Initialize Supabase client and attach to the Flask app
    app.supabase = create_client(url, key)

    # SENDGRID CONFIG
    app.config['SENDGRID_API_KEY'] = os.getenv("SENDGRID_API_KEY")
    app.config['FROM_EMAIL'] = 'imvaader@gmail.com'
    app.sendgrid_client = SendGridAPIClient(app.config['SENDGRID_API_KEY'])

    from app import routes
    routes.init_routes(app)

    return app
