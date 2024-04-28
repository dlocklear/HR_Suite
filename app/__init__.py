import os
from supabase import create_client, Client
from flask import Flask
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

from app import routes

