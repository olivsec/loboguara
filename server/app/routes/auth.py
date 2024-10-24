from flask import Blueprint, render_template, redirect, url_for, flash, send_file, request, current_app, session as flask_session
from app import db, bcrypt,csrf
from app.models import User
from app.forms import LoginForm, RegistrationForm, ResetPasswordForm, ResetPasswordTokenForm, VerifyCodeForm
from flask_login import login_user, logout_user, login_required, current_user
from app.utils.helpers import send_verification_email, generate_verification_code
from datetime import datetime, timedelta
import os
import hmac
from contextlib import contextmanager
import pyotp
import qrcode
import io
import base64

bp = Blueprint('auth', __name__)

@contextmanager
def get_session():
    session = db.session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_input = form.username.data 
        password = form.password.data

        with get_session() as db_session:
            user = db_session.query(User).filter(
                (User.username == user_input) | (User.email == user_input)
            ).first()

            if user and bcrypt.check_password_hash(user.password, password):
                if current_app.config['TWO_FACTOR_ENABLED']:  
                    if current_app.config['TWO_FACTOR_METHOD'] == 'totp':
                        
                        if not user.totp_secret:
                            flask_session['user_id'] = user.id
                            return redirect(url_for('auth.enable_totp'))  

                        
                        flask_session['user_id'] = user.id
                        return redirect(url_for('auth.verify_totp'))  

                    elif current_app.config['TWO_FACTOR_METHOD'] == 'email':
                        
                        code = generate_verification_code()
                        user.verification_code = code
                        user.verification_code_expiration = datetime.utcnow() + timedelta(minutes=10)

                        try:
                            db_session.commit()
                        except Exception as e:
                            flash('An error occurred. Please try again.', 'danger')
                            return redirect(url_for('auth.login'))

                        try:
                            
                            send_verification_email(user.email, f'Your verification code is: {code}', 'Lobo Guará Verification Code')
                            flash('A verification code has been sent to your email.', 'info')
                        except Exception as email_error:
                            
                            current_app.logger.error(f"Failed to send verification email: {email_error}")
                            flash('Error: Could not send verification email. Please contact support or check email settings.', 'danger')
                            return redirect(url_for('auth.login'))
                    
                    flask_session['user_id'] = user.id 
                    return redirect(url_for('auth.verify_code'))
                
                else:
                    
                    login_user(user)
                    flash('Logged in successfully!', 'success')
                    return redirect(url_for('main.index'))
            else:
                flash('Invalid username/email or password', 'danger')
    return render_template('login.html', form=form)



@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flask_session.clear()
    return redirect(url_for('main.index'))

@bp.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    form = VerifyCodeForm()
    if 'user_id' not in flask_session:
        return redirect(url_for('auth.login'))

    with get_session() as db_session:
        user = db_session.query(User).get(flask_session['user_id'])
        if not user:
            flash('Invalid session. Please log in again.', 'danger')
            flask_session.clear() 
            return redirect(url_for('auth.login'))

        if form.validate_on_submit():
            input_code = form.code.data
            if hmac.compare_digest(user.verification_code, input_code) and datetime.utcnow() < user.verification_code_expiration:
                login_user(user)
                user.verification_code = None
                user.verification_code_expiration = None
                try:
                    db_session.commit()
                except Exception as e:
                    db_session.rollback()
                    flash('An error occurred. Please try again.', 'danger')
                    return redirect(url_for('auth.login'))

                flask_session.pop('user_id', None)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('main.index'))
            else:
                flash('Invalid or expired verification code', 'danger')

    return render_template('verify_code.html', form=form)

@bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        with get_session() as db_session:
            user = db_session.query(User).filter_by(email=email).first()
            if user:
                token = os.urandom(24).hex()
                user.reset_token = token
                user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
                try:
                    db_session.commit()
                except Exception as e:
                    db_session.rollback()
                    flash('An error occurred. Please try again.', 'danger')
                    return redirect(url_for('auth.reset_password'))

                reset_link = url_for('auth.reset_password_token', token=token, _external=True)
                send_verification_email(user.email, f'Your username is: {user.username}\n\n Click the link to reset your password: {reset_link}', 'Lobo Guará Reset Password')
                flash('A password reset link has been sent to your email.', 'info')
            else:
                flash('Email not found!', 'danger')
    return render_template('reset_password.html', form=form)

@csrf.exempt
@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    current_app.logger.info(f"Reset Password Token Route Accessed with token: {token}")
    
    form = ResetPasswordTokenForm()
    
    with get_session() as db_session:
        user = db_session.query(User).filter_by(reset_token=token).first()
        if not user or user.reset_token_expiration < datetime.utcnow():
            current_app.logger.warning(f"Invalid or expired token for user: {user}. Redirecting.")
            flash('Invalid or expired token', 'danger')
            return redirect(url_for('auth.reset_password'))

        if request.method == 'POST' and form.validate_on_submit():
            current_app.logger.info("Form validation succeeded.")
            
            new_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = new_password
            user.reset_token = None
            user.reset_token_expiration = None

            try:
                db_session.commit()
                flash('Your password has been reset!', 'success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                current_app.logger.error(f"Error during password reset: {str(e)}")
                db_session.rollback()
                flash('An error occurred. Please try again.', 'danger')
                return redirect(url_for('auth.reset_password_token', token=token))
        elif request.method == 'POST':
            current_app.logger.warning(f"Form validation failed. Errors: {form.errors}")
            flash('Form validation failed. Please check your input.', 'danger')

    return render_template('reset_password_token.html', form=form)

@csrf.exempt
@bp.route('/admin', methods=['GET', 'POST'])
def register_superadmin():
    superadmin_exists = User.query.filter_by(is_superadmin=True).first()

    if superadmin_exists:
        return redirect(url_for('auth.login'))

    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    email=form.email.data,
                    password=hashed_password,
                    is_superadmin=True,
                    is_admin=True)

        db.session.add(user)
        db.session.commit()

        flash('Superadmin registered successfully!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register_superadmin.html', form=form)

@bp.route('/enable_totp', methods=['GET', 'POST'])
def enable_totp():
    if 'user_id' not in flask_session:
        return redirect(url_for('auth.login'))

    with get_session() as db_session:
        user = db_session.query(User).get(flask_session['user_id'])
        if not user:
            flash('Invalid session. Please log in again.', 'danger')
            flask_session.clear()
            return redirect(url_for('auth.login'))

        form = VerifyCodeForm()

        if request.method == 'GET':
            if 'totp_secret' not in flask_session:
                flask_session['totp_secret'] = pyotp.random_base32()

            
            totp_uri = pyotp.TOTP(flask_session['totp_secret']).provisioning_uri(user.email, issuer_name="Lobo Guará")

            
            qr_img = qrcode.make(totp_uri)
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")
            qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

            return render_template('enable_totp.html', form=form, qr_code=qr_code_base64)

        elif request.method == 'POST' and form.validate_on_submit():
            input_code = form.code.data
            totp = pyotp.TOTP(flask_session['totp_secret'])  

            if totp.verify(input_code):
                
                user.totp_secret = flask_session.pop('totp_secret')  
                db_session.commit()

                flash('TOTP setup successful!', 'success')
                login_user(user)
                flask_session.pop('user_id', None)
                return redirect(url_for('main.index'))
            else:
                flash('Invalid TOTP code. Please try again.', 'danger')

    return render_template('enable_totp.html', form=form)


@bp.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    if 'user_id' not in flask_session:
        return redirect(url_for('auth.login'))

    form = VerifyCodeForm()
    with get_session() as db_session:
        user = db_session.query(User).get(flask_session['user_id'])
        if not user:
            flash('Invalid session. Please log in again.', 'danger')
            flask_session.clear()
            return redirect(url_for('auth.login'))

        if form.validate_on_submit():
            totp = pyotp.TOTP(user.totp_secret)
            input_code = form.code.data

            if totp.verify(input_code):
                login_user(user)
                flash('Logged in successfully!', 'success')
                flask_session.pop('user_id', None)  
                return redirect(url_for('main.index'))
            else:
                flash('Invalid TOTP code. Please try again.', 'danger')

    return render_template('verify_totp.html', form=form)
