from datetime import datetime
from flask import current_app, render_template
from flask_mail import Message
from pytz import UTC
from app import mail
import logging

def check_and_send_notifications():
    with current_app.app_context():
        from app.models import User, UserSSLCertificate

        users = User.query.all()
        for user in users:
            certificates = UserSSLCertificate.query.filter_by(user_id=user.id).all()
            for cert in certificates:
                days_remaining = calculate_days_remaining(cert.not_after)
                if days_remaining >= 0:
                    if (cert.notify_30 and days_remaining == 30) or \
                       (cert.notify_15 and days_remaining == 15) or \
                       (cert.notify_7 and days_remaining == 7):
                        send_expiry_notification(user.email, cert.common_name, days_remaining)

def send_expiry_notification(email, domain, days_remaining):
    subject = f"SSL Certificate Expiration Alert for {domain}"
    body = f"The SSL certificate for {domain} will expire in {days_remaining} days. Please take action to renew it."
    send_email(email, subject, body)

def send_email(recipient_email, subject, body):
  

    if not isinstance(recipient_email, str):
        logging.error(f"Invalid email type: {type(recipient_email)}. Email must be a string.")
        return
    if "\n" in recipient_email or "\r" in recipient_email:
        logging.error("Email contains invalid newline characters.")
        return
    
    logging.info(f"Enviando email para: {recipient_email}")
    

    msg = Message(subject, sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[recipient_email])
    msg.html = render_template('email/email_template.html', subject=subject, body=body)
    

    try:
        mail.send(msg)
        logging.info(f"Email enviado para {recipient_email} com sucesso.")
    except Exception as e:
        logging.error(f"Erro ao enviar email para {recipient_email}: {str(e)}")

def calculate_days_remaining(expiration_date):

    if isinstance(expiration_date, datetime):
        if expiration_date.tzinfo is None:
            expiration_date = expiration_date.replace(tzinfo=UTC)
        current_time = datetime.utcnow().replace(tzinfo=UTC)
        return (expiration_date - current_time).days
    elif isinstance(expiration_date, str):
        try:
            expiration_date = datetime.fromisoformat(expiration_date)
            return calculate_days_remaining(expiration_date)
        except ValueError:
            return -1
    return -1
