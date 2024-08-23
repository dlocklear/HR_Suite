from app import send_email

def send_notification(recipient_email, subject, message):
    try:
        send_email(recipient_email, subject, message)
        print(f"Notification sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send notification to {recipient_email}: {str(e)}")


def send_notifications_to_all(message):
    users = supabase.table("users").select("email").execute().data
    for user in users:
        send_notification(user["email"], "Notification", message)


def send_notifications_to_role(role, message):
    users = supabase.table("users").select("email").eq("role", role).execute().data
    for user in users:
        send_notification(user["email"], "Notification", message)


def send_notification_to_employee(employee_id, message):
    employee = supabase.table("employees").select("email").eq("employee_id", employee_id).execute().data[0]
    send_notification(employee["email"], "Notification", message)
