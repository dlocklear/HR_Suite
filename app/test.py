import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# SMTP configuration (these should match your Supabase environment variables)
smtp_server = "smtp.postmarkapp.com"
smtp_port = 587
# Replace with your Postmark Server API Token
smtp_user = "fbf026fc-0469-4ffe-823f-c91277bd364c"
# Replace with your Postmark Server API Token
smtp_password = "fbf026fc-0469-4ffe-823f-c91277bd364c"

# Email details
# Replace with your verified sender address
from_email = "MIC2497938@maricopa.edu"
to_email = "MIC2497938@maricopa.edu"
subject = "Test Email from Supabase"
body = "Hello, World! This is a test email sent using Postmark SMTP configuration with Supabase."

# Create the email message
msg = MIMEMultipart()
msg["From"] = from_email
msg["To"] = to_email
msg["Subject"] = subject
msg.attach(MIMEText(body, "plain"))

# Send the email
try:
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Secure the connection
        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, to_email, msg.as_string())
        print("Email sent successfully")
except Exception as e:
    print(f"Error sending email: {e}")
