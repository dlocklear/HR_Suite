import os
from supabase import create_client, Client
from dotenv import load_dotenv
import logging

# Load environment variables from .env file
load_dotenv()

# Initialize logging
logging.basicConfig(level=logging.DEBUG)

# Retrieve Supabase URL and Key from environment variables
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_ANON_KEY")

# Check if Supabase URL and Key are available
if not url or not key:
    logging.error("Supabase URL or Key not found. Please check the .env file.")
else:
    logging.info(f"Supabase URL: {url}")
    logging.info(f"Supabase Key: {key[:10]}...")  # Log only the first 10 characters of the key for security

# Create Supabase client
supabase = create_client(url, key)

def test_supabase_query():
    try:
        employee_name = 'megan'
        query = f"%{employee_name}%"
        response = supabase.table('employees').select('*').ilike('employee_name', query).execute()
        logging.info(f"Supabase response: {response}")
        if response.data:
            logging.info(f"Employee data: {response.data}")
        else:
            logging.warning("No employee data found.")
    except Exception as e:
        logging.error(f"Error fetching employee details: {e}")

# Run the test query
test_supabase_query()
