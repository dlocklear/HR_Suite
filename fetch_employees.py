import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Set up Supabase client
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY')

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def fetch_employees():
    try:
        response = supabase.table('employees').select('*').execute()
        employees = response.data
        if employees:
            for employee in employees:
                print(f"ID: {employee['employee_id']}, Name: {employee['employee_name']}")
        else:
            print("No employees found.")
    except Exception as e:
        print(f"Error fetching employees: {e}")

if __name__ == '__main__':
    fetch_employees()
