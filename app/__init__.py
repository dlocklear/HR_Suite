from sendgrid.helpers.mail import Mail
from sendgrid import SendGridAPIClient
import os
from supabase import create_client, Client
from flask import Flask
from flask_bcrypt import Bcrypt
from config import Config
from dotenv import load_dotenv

load_dotenv()

bcrypt = Bcrypt()

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'csv'}

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    bcrypt.init_app(app)

    # Initialize Supabase client and attach to the Flask app
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_ANON_KEY")
    app.supabase = create_client(url, key)

    # Configure upload folder and allowed extensions
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS

    # Ensure the upload directory exists
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    # Debug: print the upload folder path
    print(f"Upload folder path: {UPLOAD_FOLDER}")

    from app.routes import init_routes
    init_routes(app)

    return app
