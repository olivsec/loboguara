from flask import Blueprint, render_template, redirect, url_for, flash, request
from app import db, bcrypt
from app.models import User, DashboardMetrics, Timezone
from app.forms import RegistrationForm, UpdatePermissionsForm, DeleteForm, UpdateEmailForm, UpdateTimezoneForm, UpdatePasswordForm
from flask_login import login_required, current_user
from app.utils.helpers import admin_required
import bcrypt
import logging
from contextlib import contextmanager
from sqlalchemy.exc import OperationalError, DisconnectionError, IntegrityError

bp = Blueprint('admin', __name__)

logger = logging.getLogger('admin_logger')

@contextmanager
def get_session():

    session = db.session()
    try:
        yield session
        session.commit()
    except (OperationalError, DisconnectionError) as e:
        session.rollback()
        logger.error(f"Database connection error: {e}")
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error during session operation: {e}")
        raise
    finally:
        session.close()

@bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    if not current_user.is_superadmin:
        flash('Only the superadmin can access this page.', 'danger')
        return redirect(url_for('main.index'))

    metrics = DashboardMetrics.query.order_by(DashboardMetrics.timestamp.desc()).first()

    if metrics is None:
        flash('No dashboard data available.', 'warning')
        return render_template('admin_dashboard.html', metrics=None)

    return render_template('admin_dashboard.html', metrics=metrics)

@bp.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    users_pagination = User.query.paginate(page=page, per_page=per_page)
    
    form = DeleteForm()
    
    return render_template('admin_users.html', users=users_pagination.items, users_pagination=users_pagination, form=form)

@bp.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if not current_user.is_superadmin:
        flash('Only the superadmin can create new users.', 'danger')
        return redirect(url_for('admin.admin_users'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        is_admin = form.is_admin.data
        is_superadmin = form.is_superadmin.data

        new_user = User(username=username, email=email, password=password, is_admin=is_admin, is_superadmin=is_superadmin)
        
        with get_session() as session:
            session.add(new_user)
            try:
                session.commit()
                flash('New user created successfully!', 'success')
                return redirect(url_for('admin.admin_users'))
            except Exception as e:
                flash('Error creating new user. Please try again.', 'danger')

    return render_template('register.html', form=form)

@bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    email_form = UpdateEmailForm()
    password_form = UpdatePasswordForm()
    timezone_form = UpdateTimezoneForm()
    permission_form = UpdatePermissionsForm()

    if email_form.submit.data and email_form.validate_on_submit():
        user.email = email_form.email.data
        db.session.commit()
        flash('Email updated successfully!', 'success')
        return redirect(url_for('admin.edit_user', user_id=user_id))

    if password_form.submit.data and password_form.validate_on_submit():
        user.password = bcrypt.generate_password_hash(password_form.password.data).decode('utf-8')
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('admin.edit_user', user_id=user_id))

    if timezone_form.submit_timezone.data and timezone_form.validate_on_submit():
        user.idtimezone = timezone_form.timezone.data
        db.session.commit()
        flash('Timezone updated successfully!', 'success')
        return redirect(url_for('admin.edit_user', user_id=user_id))

    if permission_form.submit_permissions.data and permission_form.validate_on_submit():
        user.is_admin = permission_form.is_admin.data
        user.is_superadmin = permission_form.is_superadmin.data
        db.session.commit()
        flash('Permissions updated successfully!', 'success')
        return redirect(url_for('admin.edit_user', user_id=user_id))

    if request.method == 'GET':
        email_form.email.data = user.email
        timezone_form.timezone.data = user.idtimezone if user.idtimezone is not None else 1
        permission_form.is_admin.data = user.is_admin
        permission_form.is_superadmin.data = user.is_superadmin

    return render_template('edit_user.html', 
                           email_form=email_form, 
                           password_form=password_form, 
                           timezone_form=timezone_form, 
                           permission_form=permission_form, 
                           user=user)


@bp.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    with get_session() as session:
        try:
            session.delete(user)
            session.commit()
            logger.info(f"User deleted: {user.username}")
            flash('User deleted successfully!', 'success')
        except Exception as e:
            logger.error(f"Error deleting user {user.username}: {e}")
            flash('Error deleting user. Please try again.', 'danger')
    return redirect(url_for('admin.admin_users'))


@bp.route('/admin/users/<int:user_id>/reset_totp', methods=['POST'])
@login_required
@admin_required
def reset_totp(user_id):
    user = User.query.get_or_404(user_id)
    
    if not user.totp_secret:
        flash('TOTP is not enabled for this user.', 'info')
        return redirect(url_for('admin.edit_user', user_id=user_id))

    user.totp_secret = None
    try:
        db.session.commit()
        flash('TOTP has been reset successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error resetting TOTP. Please try again.', 'danger')

    return redirect(url_for('admin.edit_user', user_id=user_id))
