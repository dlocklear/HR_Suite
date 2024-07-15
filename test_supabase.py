import os
from supabase import create_client, Client
from dotenv import load_dotenv
import logging

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_ANON_KEY")

if not url or not key:
    logging.error("Supabase URL or Key not found. Please check the .env file.")
else:
    logging.info(f"Supabase URL: {url}")
    logging.info(f"Supabase Key: {key[:10]}...")  # Log only the first 10 characters of the key for security

supabase = create_client(url, key)

def test_supabase_query():
    try:
        employee_name = 'megan'
        query = f"%{employee_name}%"
        logging.info(f"Executing query: {query}")
        response = supabase.table('employees').select('*').ilike('employee_name', query).execute()
        
        # Log the full response object
        logging.info(f"Full Supabase response: {response}")
        
        # Log the raw response
        logging.info(f"Raw Supabase response: {response.raw}")

        # Log the data part of the response
        logging.info(f"Supabase response data: {response.data}")

        if response.data:
            logging.info(f"Employee data: {response.data}")
        else:
            logging.warning("No employee data found.")
    except Exception as e:
        logging.error(f"Error fetching employee details: {e}")

test_supabase_query()
