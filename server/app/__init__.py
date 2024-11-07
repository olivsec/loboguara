import os
from flask import Flask, request, jsonify, current_app, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_restful import Api
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
from flask_migrate import Migrate
from apscheduler.schedulers.background import BackgroundScheduler
from contextlib import contextmanager
import pytz
from functools import partial
import json
import atexit
from flask_socketio import SocketIO
from functools import wraps

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()
api = Api()
limiter = Limiter(key_func=get_remote_address, storage_uri="redis://localhost:6379/0")
socketio = SocketIO()

@contextmanager
def get_session():

    session = db.session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logging.error(f"Erro na sessão do banco de dados: {str(e)}")
        raise
    finally:
        session.close()

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.config.from_object('app.config.Config')

    def json_loads_filter(data):
        try:
            return json.loads(data)
        except (ValueError, TypeError):
            return {}

    app.jinja_env.filters['json_loads'] = json_loads_filter

    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'max_overflow': 5,
        'pool_timeout': 30,
        'pool_recycle': 1800
    }

    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    api.init_app(app)
    limiter.init_app(app)

    socketio.init_app(app, async_mode='eventlet')

    def last_filter(seq):
        return seq[-1] if seq else None

    app.jinja_env.filters['last'] = last_filter
    app.logger.info("Filtro personalizado Jinja2 'last' registrado.")

    with app.app_context():
        db.create_all()
        # init_timezones()

    from app.routes import auth, admin, main, domainscan, webpathscan, urlscan, urlmonitoring, redirection

    app.register_blueprint(auth.bp)
    app.register_blueprint(admin.bp)
    if 'main' not in app.blueprints:
        app.register_blueprint(main.bp)
    app.register_blueprint(domainscan.bp)
    app.register_blueprint(urlscan.bp)
    app.register_blueprint(urlmonitoring.bp)
    app.register_blueprint(webpathscan.bp)
    app.register_blueprint(redirection.bp)

    from app.errors import register_error_handlers
    register_error_handlers(app)

    configure_logging(app)
    register_user_loader()

    @app.route('/urlscan-files/<path:filename>')
    def serve_urlscan_file(filename):
        path = '/opt/loboguara/urlscan-files'
        current_app.logger.info(f"Serving {filename} from {path}")
        return send_from_directory(path, filename)

    @app.template_filter('to_user_timezone')
    def to_user_timezone(utc_dt, user_timezone):

        if not utc_dt:
            return ''
        if user_timezone:
            local_tz = pytz.timezone(user_timezone.pytz_name)
            return utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S')
        else:
            return utc_dt.strftime('%Y-%m-%d %H:%M:%S')

    return app

def init_timezones():
    from app.models import Timezone
    timezones = {
        "(UTC-12:00) International Date Line West": "Etc/GMT+12",
        "(UTC-11:00) Coordinated Universal Time-11": "Etc/GMT+11",
        "(UTC-10:00) Hawaii": "Pacific/Honolulu",
        "(UTC-09:00) Alaska": "America/Anchorage",
        "(UTC-08:00) Pacific Time (US & Canada)": "America/Los_Angeles",
        "(UTC-07:00) Mountain Time (US & Canada)": "America/Denver",
        "(UTC-06:00) Central Time (US & Canada)": "America/Chicago",
        "(UTC-05:00) Eastern Time (US & Canada)": "America/New_York",
        "(UTC-04:00) Atlantic Time (Canada)": "America/Halifax",
        "(UTC-03:00) Brasília": "America/Sao_Paulo",
        "(UTC-02:00) Mid-Atlantic": "Etc/GMT+2",
        "(UTC-01:00) Azores": "Atlantic/Azores",
        "(UTC+00:00) Monróvia, Reiquiavique": "UTC",
        "(UTC+01:00) West Central Africa": "Africa/Lagos",
        "(UTC+02:00) Cairo": "Africa/Cairo",
        "(UTC+03:00) Moscow, St. Petersburg, Volgograd": "Europe/Moscow",
        "(UTC+04:00) Abu Dhabi, Muscat": "Asia/Dubai",
        "(UTC+05:00) Islamabad, Karachi": "Asia/Karachi",
        "(UTC+06:00) Astana, Dhaka": "Asia/Dhaka",
        "(UTC+07:00) Bangkok, Hanoi, Jakarta": "Asia/Bangkok",
        "(UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi": "Asia/Shanghai",
        "(UTC+09:00) Tokyo, Osaka, Sapporo": "Asia/Tokyo",
        "(UTC+10:00) Brisbane": "Australia/Brisbane",
        "(UTC+11:00) Solomon Islands, New Caledonia": "Pacific/Guadalcanal",
        "(UTC+12:00) Fiji, Marshall Islands": "Pacific/Fiji"
    }

    with get_session() as session:
        for name, pytz_name in timezones.items():
            timezone = session.query(Timezone).filter_by(name=name).first()
            if timezone:
                if timezone.pytz_name != pytz_name:
                    timezone.pytz_name = pytz_name
            else:
                session.add(Timezone(name=name, pytz_name=pytz_name))

def start_scheduler(app):
    from app.routes.urlmonitoring import check_monitored_urls

    scheduler = BackgroundScheduler()

    scheduler.add_job(partial(check_monitored_urls, app), 'interval', minutes=1)

    scheduler.start()
    app.logger.info('APScheduler started.')

def csrf_exempt_bp(bp):
    csrf.exempt(bp)

def configure_logging(app):
    if not os.path.exists('logs'):
        os.makedirs('/opt/loboguara/logs', exist_ok=True)

    log_file = app.config.get('LOG_FILE', '/opt/loboguara/logs/loboguara.log')

    if not any(isinstance(handler, RotatingFileHandler) for handler in app.logger.handlers):
        file_handler = RotatingFileHandler(log_file, maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.ERROR)
        app.logger.addHandler(file_handler)

    app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
    app.logger.info('Lobo Guará startup')

    atexit.register(close_log_handlers, app)

def close_log_handlers(app):

    for handler in app.logger.handlers:
        handler.close()
        app.logger.removeHandler(handler)

def register_user_loader():
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

def token_required(f):
    from app.utils.security import verify_token

    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-tokens')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        user = verify_token(token)
        if not user:
            return jsonify({'message': 'Token is invalid or expired!'}), 401
        return f(user, *args, **kwargs)

    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(user, *args, **kwargs):
        if not user.is_admin and not user.is_superadmin:
            return jsonify({'message': 'Admin access required!'}), 403
        return f(user, *args, **kwargs)

    return decorated
