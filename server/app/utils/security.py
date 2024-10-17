from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from app.models import User

def generate_token(user_id, expiration=3600):
    s = Serializer(current_app.config['SECRET_KEY'], expiration)
    return s.dumps({'user_id': user_id}).decode('utf-8')

def verify_token(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except:
        return None
    return User.query.get(data['user_id'])