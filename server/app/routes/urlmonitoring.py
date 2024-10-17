from flask import Blueprint, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from datetime import datetime 
import logging
from app import db, get_session
from app.models import URLMonitoring, User
import requests
from threading import Thread
import uuid
from app.jobs.notificationjobs import send_email

bp = Blueprint('urlmonitoring', __name__, url_prefix='/monitoring')

logger = logging.getLogger('flask.app')

def update_scan_status(scan):

    with get_session() as session:
        monitoring = session.query(URLMonitoring).filter_by(scan_id=scan.id).first()
        if monitoring:
            monitoring.status = 'completed'
            session.add(monitoring)
            session.commit()
            logger.info(f"Monitoring {monitoring.id} updated to 'completed'.")

def check_url_status(url):
    try:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0'
        })
        response = session.get(url, allow_redirects=True, timeout=10)
        if response.status_code == 200:
            logger.info(f"URL {url} returned status code 200.")
            return True
        else:
            logger.info(f"URL {url} returned status code {response.status_code}.")
            return False
    except requests.RequestException as e:
        logger.error(f"Error checking URL {url}: {str(e)}")
        return False

def perform_monitoring(monitoring_id, app):

    with app.app_context(): 
        with get_session() as session:
            monitoring = session.query(URLMonitoring).get(monitoring_id)

            if monitoring and check_url_status(monitoring.url):
                from app.routes.urlscan import run_urlscan
                from app.models import URLScan

                logger.info("Before the scan.")
                new_scan = URLScan(
                    id=uuid.uuid4(),
                    url=monitoring.url,
                    user_id=monitoring.user_id,
                    status='in progress',
                    timestamp=datetime.utcnow()
                )
                logger.info("After the scan.")
                session.add(new_scan)
                session.commit()

                monitoring.scan_id = new_scan.id
                monitoring.status = 'scan in progress'
                monitoring.last_checked = datetime.utcnow()
                session.add(monitoring)
                session.commit()

                def update_scan_status(scan):
                    with app.app_context():
                        scan.status = 'completed'
                        monitoring.status = 'completed'
                        session.add(scan)
                        session.add(monitoring)
                        session.commit()

                        user = User.query.get(monitoring.user_id)
                        send_email(user.email, 'Scan Completed', f'Scan for URL {monitoring.url} has been completed successfully.')
                        logger.info(f"Scan completed for {monitoring.url}, status updated.")

                scan_thread = Thread(target=lambda: run_urlscan(new_scan, callback=update_scan_status))
                scan_thread.start()

                logger.info(f"Scan started for {monitoring.url}, monitoring updated.")
            else:
                monitoring.last_checked = datetime.utcnow()
                session.add(monitoring)
                session.commit()
                logger.info(f"URL {monitoring.url} is not online yet.")

def check_monitored_urls(app):

    with app.app_context():
        with get_session() as session:
            monitorings = session.query(URLMonitoring).filter_by(status='in monitoring').all()
            for monitoring in monitorings:
                if (datetime.utcnow() - monitoring.last_checked).total_seconds() >= monitoring.scan_interval:
                    logger.info(f"Checking monitored URL: {monitoring.url}")
                    thread = Thread(target=perform_monitoring, args=(monitoring.id, app))
                    thread.start()

@bp.route('/urlmonitoring', methods=['GET', 'POST'])
@login_required
def url_monitoring():
    from app.forms import URLMonitoringForm
    from app.models import URLMonitoring, URLScan

    form = URLMonitoringForm()
    if form.validate_on_submit():
        url = form.url.data
        scan_interval = int(form.scan_interval.data)

        new_monitoring = URLMonitoring(
            id=uuid.uuid4(), 
            url=url, 
            user_id=current_user.id, 
            scan_interval=scan_interval, 
            status='in monitoring', 
            last_checked=datetime.utcnow(),
            timestamp=datetime.utcnow()
        )
        db.session.add(new_monitoring)
        db.session.commit()

        flash('URL monitoring started!', 'success')
        return redirect(url_for('urlmonitoring.url_monitoring'))

    user_monitorings = URLMonitoring.query.filter_by(user_id=current_user.id).order_by(URLMonitoring.timestamp.desc()).all()

    for monitoring in user_monitorings:
        monitoring.scan = URLScan.query.filter_by(id=monitoring.scan_id).first() if monitoring.scan_id else None

    return render_template('urlmonitoring.html', form=form, monitorings=user_monitorings)

@bp.route('/view_monitoring/<uuid:monitoring_id>')
@login_required
def view_monitoring(monitoring_id):
    from app.models import URLMonitoring

    monitoring = URLMonitoring.query.get_or_404(monitoring_id)
    return render_template('view_mu.html', monitoring=monitoring)

@bp.route('/cancel_monitoring/<uuid:monitoring_id>', methods=['POST'])
@login_required
def cancel_monitoring(monitoring_id):
    from app.models import URLMonitoring

    monitoring = URLMonitoring.query.get_or_404(monitoring_id)
    if monitoring.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('urlmonitoring.url_monitoring'))

    monitoring.status = 'cancelled'
    db.session.commit()

    flash('Monitoring canceled.', 'success')
    return redirect(url_for('urlmonitoring.url_monitoring'))

@bp.route('/monitor_again/<uuid:monitoring_id>', methods=['POST'])
@login_required
def monitor_again(monitoring_id):
    from app.models import URLMonitoring

    monitoring = URLMonitoring.query.get_or_404(monitoring_id)
    if monitoring.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('urlmonitoring.url_monitoring'))

    monitoring.status = 'in monitoring'
    db.session.commit()

    flash('Monitoring restarted.', 'success')
    return redirect(url_for('urlmonitoring.url_monitoring'))
