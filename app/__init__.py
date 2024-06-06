from sendgrid.helpers.mail import Mail
from sendgrid import SendGridAPIClient
import os
from supabase import create_client, Client
from flask import Flask
from flask_bcrypt import Bcrypt
from config import Config
from dotenv import load_dotenv
import os
from supabase import create_client, Client

load_dotenv()

bcrypt = Bcrypt()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    bcrypt.init_app(app)

    # Initialize Supabase client and attach to the Flask app
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_ANON_KEY")
    app.supabase = create_client(url, key)

    from app.routes import init_routes
    init_routes(app)

    return app
