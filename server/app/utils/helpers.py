from flask import current_app, flash, redirect, url_for
from functools import wraps
from flask_login import current_user
from flask_mail import Message
import json
import re

def send_verification_email(to, body, subject):
    from app import mail

    msg = Message(
        subject,
        recipients=[to],
        body=body,
        sender=current_app.config['MAIL_DEFAULT_SENDER']
    )

    with mail.connect() as conn:
        conn.send(msg)

def generate_verification_code():
    from random import randint
    return f'{randint(100000, 999999):06}'

def clean_and_fix_json(content):
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    if content.startswith('"') and content.endswith('"'):
        content = content[1:-1]

    content = content.replace('\\"', '"')
    content = re.sub(r'(\w+):(\w+)', r'"\1": "\2"', content)
    content = re.sub(r'("Content": ".*?)(hash code: )', r'\1", "hash code": "', content)
    content = re.sub(r'(hash code": ".*?)(Threat actor description: )', r'\1", "Threat actor description": "', content)
    content = re.sub(r'(Threat actor description": ".*?)(Target victim website:)', r'\1", "Target victim website": "', content)
    content = re.sub(r'(Target victim website": ".*?)("Detection Date":)', r'\1", "Detection Date": ', content)

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        current_app.logger.error(f"Falha ao corrigir JSON: {e}")
        return {"Content": content}

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Acesso negado.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function
