from sendgrid.helpers.mail import Mail as SendGridMail
import logging


def send_confirmation_email(sg_client, from_email, to_email, subject, html_content):
    message = SendGridMail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        html_content=html_content
    )
    try:
        response = sg_client.send(message)
        logging.info(f"Email sent with status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")
        raise e
