from utils.email_utils import send_confirmation_email
from app import supabase

def send_notification(sg_client, recipient_email, subject, message):
    from_email = "no-reply@yourcompany.com"  # Replace with your company's email
    html_content = f"<p>{message}</p>"

    try:
        send_confirmation_email(
            sg_client=sg_client,
            from_email=from_email,
            to_email=recipient_email,
            subject=subject,
            html_content=html_content
        )
        print(f"Notification sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send notification to {recipient_email}: {str(e)}")

def send_notifications_to_all(sg_client, message):
    users = supabase.table("users").select("email").execute().data
    for user in users:
        send_notification(sg_client, user["email"], "Notification", message)

def send_notifications_to_role(sg_client, role, message):
    users = supabase.table("users").select("email").eq("role", role).execute().data
    for user in users:
        send_notification(sg_client, user["email"], f"{role} Notification", message)

def send_notification_to_employee(sg_client, employee_id, message):
    employee = supabase.table("employees").select("email").eq("employee_id", employee_id).execute().data[0]
    send_notification(sg_client, employee["email"], "Personal Notification", message)
