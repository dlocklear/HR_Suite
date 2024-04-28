import os
from supabase import create_client, Client
from flask import Flask
from dotenv import load_dotenv
load_dotenv()


def create_app():
    app = Flask(__name__)

    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_ANON_KEY")
    supabase: Client = create_client(url, key)

    from app.routes import init_routes
    init_routes(app)

    return app
