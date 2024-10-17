import subprocess
import json
from flask import Blueprint, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from datetime import datetime
import logging
import threading
import signal
from concurrent.futures import ThreadPoolExecutor
from app import db, create_app, socketio
import whois
from flask_wtf.csrf import CSRFProtect
from app.jobs.notificationjobs import send_email

csrf = CSRFProtect()

bp = Blueprint('domainscan', __name__)

MAX_CONCURRENT_SCANS = 10
scan_queue = []
scan_threads = []
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)

logger = logging.getLogger('flask.app') 

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException

signal.signal(signal.SIGALRM, timeout_handler)

def execute_whois(domain):
    try:
        domain_info = whois.whois(domain)
        return str(domain_info)
    except Exception as e:
        logger.error(f"Error executing WHOIS: {e}")
        return None

def execute_subfinder(domain, id_scan):
    try:
        subfinder_path = current_app.config['SUBFINDER_PATH']
        command = [
            subfinder_path, '-d', domain, '-silent'
        ]
        logger.info(f"Executing Subfinder: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, timeout=1800)

        if result.returncode == 0:
            output = result.stdout
            logger.info(f"Subfinder output:\n{output}")

            subdomains = output.splitlines()

            additional_info = []

            return subdomains, additional_info
        else:
            logger.error(f"Error executing Subfinder: {result.stderr}")
            return None, None
    except TimeoutException:
        logger.warning(f"Subfinder timed out for {domain}")
        return None, None
    except Exception as e:
        logger.error(f"Error executing Subfinder: {e}")
        return None, None

def run_domainscan(scan):
    app = create_app()
    with app.app_context():
        from app.models import User, DomainScan

        scan = db.session.merge(scan)
        if scan.status not in ['waiting', 'in progress']:
            logger.info(f"Scan with status {scan.status} will not be processed again: {scan.domain}")
            return

        logger.info(f"Starting scan for domain: {scan.domain}")

        scan.status = 'in progress'
        db.session.add(scan)
        db.session.commit()
        socketio.emit('update', {'id': str(scan.id), 'status': scan.status})

        domain = scan.domain

        whois_result = execute_whois(domain)
        if whois_result is None:
            scan.status = 'error'
            db.session.add(scan)
            db.session.commit()
            socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
            return

        subdomains, additional_info = execute_subfinder(domain, scan.id)
        if subdomains is None or additional_info is None:
            scan.status = 'error'
            db.session.add(scan)
            db.session.commit()
            socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
            return

        scan.whois_result = whois_result
        scan.subdomains = json.dumps(subdomains)
        scan.additional_info = "\n".join(additional_info)
        scan.status = 'completed'
        
        try:
            db.session.add(scan)
            db.session.commit()
            socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
            logger.info(f"Scan with 'completed' status added to the database: {scan.domain}")
        except Exception as e:
            logger.error(f"Error adding scan with 'completed' status to the database: {e}")

        if scan.alert_enabled:
            user = User.query.get(scan.user_id)
            send_email(user.email, 'Domain Scan Completed', f'The scan for domain {scan.domain} has been completed.')
            logger.info(f"Notification email sent to user: {user.email}")

def process_queue(scan=None):
    global scan_threads
    if scan:
        scan_queue.append(scan)
        logger.info(f"Scan added to queue: {scan.domain}")

    while len(scan_threads) < MAX_CONCURRENT_SCANS and scan_queue:
        scan = scan_queue.pop(0)
        if scan.status == 'waiting':
            thread = threading.Thread(target=run_domainscan, args=(scan,))
            thread.start()
            scan_threads.append(thread)
            logger.info(f"Domain scan thread started for: {scan.domain}")
        else:
            logger.info(f"Domain scan with status {scan.status} will not be started: {scan.domain}")

    for thread in scan_threads:
        if not thread.is_alive():
            scan_threads.remove(thread)
            logger.info('Completed domain scan thread removed')

    from app.models import DomainScan
    waiting_scans = DomainScan.query.filter_by(status='waiting').all()
    for waiting_scan in waiting_scans:
        if waiting_scan not in scan_queue:
            scan_queue.append(waiting_scan)
            logger.info(f"Waiting domain scan added to queue: {waiting_scan.domain}")

@bp.route('/domainscan', methods=['GET', 'POST'])
@login_required
def domainscan():
    from app.forms import DomainScanForm
    from app.models import DomainScan

    form = DomainScanForm()
    if form.validate_on_submit():
        domain = form.domain.data
        alert_enabled = form.alert_enabled.data

        new_scan = DomainScan(domain=domain, user_id=current_user.id, status='waiting', alert_enabled=alert_enabled, timestamp=datetime.utcnow())
        db.session.add(new_scan)
        db.session.commit()

        process_queue(new_scan)

        flash('Domain scan started!', 'success')
        return redirect(url_for('domainscan.domainscan'))

    user_scans = DomainScan.query.filter_by(user_id=current_user.id).order_by(DomainScan.timestamp.desc()).all()
    return render_template('domainscan.html', form=form, scans=user_scans)

@bp.route('/view_domainscan/<uuid:scan_id>')
@login_required
def view_domainscan(scan_id):
    from app.models import DomainScan
    import json
    logger.debug(f"Fetching scan with id: {scan_id}")

    scan = DomainScan.query.get_or_404(scan_id)
    logger.debug(f"Scan fetched: {scan}")

    scan.whois_result = json.loads(scan.whois_result) if isinstance(scan.whois_result, str) else scan.whois_result
    return render_template('view_domainscan.html', scan=scan)

@bp.route('/rescan_domain/<uuid:scan_id>', methods=['POST'])
@login_required
@csrf.exempt
def rescan_domain(scan_id):
    from app.models import DomainScan

    scan = DomainScan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('domainscan.domainscan'))

    if DomainScan.query.filter_by(user_id=current_user.id, status='in progress').count() < MAX_CONCURRENT_SCANS:
        scan.status = 'waiting'
        db.session.commit()
        socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
        process_queue(scan)
        flash('Rescan started.', 'success')
    else:
        flash('You have reached the limit of simultaneous scans.', 'danger')

    return redirect(url_for('domainscan.domainscan'))

@bp.route('/cancel_domain/<uuid:scan_id>', methods=['POST'])
@login_required
def cancel_domain(scan_id):
    from app.models import DomainScan

    scan = DomainScan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
    elif scan.status == 'waiting':
        scan.status = 'cancelled'
        db.session.commit()
        socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
        flash('Scan cancelled successfully.', 'success')
    else:
        flash('It is not possible to cancel this scan at this time.', 'danger')

    return redirect(url_for('domainscan.domainscan'))
