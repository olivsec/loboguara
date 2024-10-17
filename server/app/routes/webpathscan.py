import subprocess
import json
from flask import Blueprint, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from datetime import datetime
import os
import logging
import re
from concurrent.futures import ThreadPoolExecutor
import threading
import signal
from app import db, create_app, socketio
from flask_wtf.csrf import CSRFProtect
from app.jobs.notificationjobs import send_email

csrf = CSRFProtect()

bp = Blueprint('webpathscan', __name__)

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

logger = logging.getLogger('flask.app')

def execute_wafw00f(url):
    logger.info(f"Starting WAF detection for URL: {url}")
    try:
        wafw00f_path = '/opt/loboguara/bin/wafw00f'
        logger.info(f"Executing wafw00f command: {wafw00f_path} {url}")
        
        result = subprocess.run([wafw00f_path, url], capture_output=True, text=True)

        if result.returncode == 0:
            output = result.stdout
            logger.info(f"wafw00f command output: {output}")

            match = re.search(r'behind (.+) WAF', output)
            if match:
                waf_name = match.group(1).strip()
                logger.info(f"WAF detected: {waf_name}")
                return waf_name
            else:
                logger.warning(f"No WAF detected in the output of wafw00f for URL: {url}")
        else:
            logger.error(f"wafw00f command failed with return code {result.returncode}")
            logger.error(f"wafw00f stderr: {result.stderr}")
        
        return None
    except Exception as e:
        logger.error(f"Error executing wafw00f for URL {url}: {e}")
        return None

def execute_ffuf(url, ffuf_output, bypass_waf, wordlist):
    ffuf_path = current_app.config['FFUF_PATH']
    wordlist_path = os.path.join('/opt/loboguara/wordlists/Web-Content', wordlist) 
    logger.info(f"Starting FFUF for {url} with output in {ffuf_output} using wordlist {wordlist_path}")

    try:
        signal.alarm(3600)
        command = [
            ffuf_path,
            '-u', f'{url}/FUZZ',
            '-w', wordlist_path,
            '-o', ffuf_output,
            '-of', 'json'
        ]
        
        if bypass_waf:
            command.extend([
                '-t', '5',
                '-p', '0.5',
                '-H', 'User-Agent: RandomUserAgent'
            ])
        else:
            command.extend(['-t', '20'])

        result = subprocess.run(command, capture_output=True, text=True)
        signal.alarm(0)

        if result.returncode != 0:
            logger.error(f"Error executing FFUF: {result.stderr}")
            return None, False

        return ffuf_output, False

    except TimeoutException:
        logger.warning(f"FFUF timed out for {url}")
        signal.alarm(0)
        return None, False
    except Exception as e:
        logger.error(f"Unexpected error executing FFUF: {e}")
        return None, False

def is_waf_block_page(content):
    waf_signatures = [
        "Access Denied", "403 Forbidden", "Blocked by", "WAF", "Web Application Firewall"
    ]
    return any(signature in content for signature in waf_signatures)

def run_webpathscan(scan):
    app = create_app()
    with app.app_context():
        from app.models import User

        scan = db.session.merge(scan)
        if scan.status not in ['waiting', 'in progress']:
            logger.info(f"Scan with status {scan.status} will not be processed again: {scan.url}")
            return

        logger.info(f"Starting scan for URL: {scan.url}")

        scan.status = 'in progress'
        logger.info(f"Adding scan with status 'in progress' to the database: {scan.url}")
        db.session.add(scan)
        db.session.commit()
        socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
        logger.info(f"Scan with status 'in progress' added to the database: {scan.url}")

        url = scan.url

        waf_name = execute_wafw00f(url)
        scan.waf_detected = bool(waf_name)
        scan.waf_name = waf_name
        logger.info(f"WAF detected: {waf_name}" if waf_name else "No WAF detected")

        if scan.waf_detected:
            logger.warning('WAF detected, the scan may take longer to avoid blocks.')

        results = []
        processed_urls = set()

        ffuf_output = f'/tmp/{url.replace("http://", "").replace("https://", "").replace("/", "_")}_ffuf.json'
        logger.info(f"Expected output file: {ffuf_output}")

        wordlist = scan.wordlist
        content, waf_detected = execute_ffuf(url, ffuf_output, bypass_waf=scan.waf_detected, wordlist=wordlist)

        if not content:
            logger.info(f"Error executing FFUF for {url} or no content returned")
            scan.status = 'error'
            logger.info(f"Adding scan with status 'error' to the database: {scan.url}")
            db.session.add(scan)
            db.session.commit()
            socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
            logger.info(f"Scan with status 'error' added to the database: {scan.url}")
            return

        try:
            with open(ffuf_output, 'r') as f:
                ffuf_results = json.load(f)

            logger.info(f"FFUF output content: {ffuf_results}")

            if 'results' in ffuf_results and ffuf_results['results']:
                for result in ffuf_results['results']:
                    status_code = result['status']
                    ffuf_url = result['url']

                    if status_code in [200, 301, 302, 401, 403, 405, 500, 503]:
                        if ffuf_url not in processed_urls:
                            processed_urls.add(ffuf_url)
                            results.append({'url': ffuf_url, 'status_code': status_code})
            else:
                logger.error("No results found in FFUF output file.")
                scan.status = 'no results'
                db.session.add(scan)
                db.session.commit()
                return
        except Exception as e:
            logger.error(f"Error processing FFUF output file: {e}")
            scan.status = 'error'
            db.session.add(scan)
            db.session.commit()
            return

        if not results:
            logger.info(f"No web paths found for URL: {url}")
            scan.status = 'no web path found'
            logger.info(f"Adding scan with status 'no web path found' to the database: {scan.url}")
            db.session.add(scan)
            db.session.commit()
            socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
            return

        logger.info(f"Scan results: {results}")

        max_results = 500
        filtered_results = results[:max_results]

        scan.result = json.dumps(filtered_results)

        scan.status = 'completed'
        logger.info(f"Adding scan with status 'completed' to the database: {scan.url}")

        try:
            db.session.add(scan)
            db.session.commit()
            socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
            logger.info(f"Scan with status 'completed' successfully added to the database: {scan.url}")
        except Exception as e:
            logger.error(f"Error adding scan with status 'completed' to the database: {e}")

        if scan.alert_enabled:
            user = User.query.get(scan.user_id)
            send_email(user.email, 'Scan Completed', f'The scan for URL {scan.url} has been completed. WAF detected: {scan.waf_name}')
            logger.info(f"Notification email sent to user: {user.email}")


def process_queue(scan=None):
    global scan_threads
    if scan:
        scan_queue.append(scan)
        logger.info(f"Scan added to queue: {scan.url}")

    while len(scan_threads) < MAX_CONCURRENT_SCANS and scan_queue:
        scan = scan_queue.pop(0)
        if scan.status == 'waiting':
            thread = threading.Thread(target=run_webpathscan, args=(scan,))
            thread.start()
            scan_threads.append(thread)
            logger.info(f"Scan thread started for: {scan.url}")
        else:
            logger.info(f"Scan with status {scan.status} will not be started: {scan.url}")

    for thread in scan_threads:
        if not thread.is_alive():
            scan_threads.remove(thread)
            logger.info('Completed scan thread removed')

    from app.models import WebPathScan
    waiting_scans = WebPathScan.query.filter_by(status='waiting').all()
    for waiting_scan in waiting_scans:
        if waiting_scan not in scan_queue:
            scan_queue.append(waiting_scan)
            logger.info(f"Waiting scan added to queue: {waiting_scan.url}")

@bp.route('/webpathscan', methods=['GET', 'POST'])
@login_required
def webpathscan():
    from app.forms import WebPathScanForm
    from app.models import WebPathScan

    form = WebPathScanForm()
    if form.validate_on_submit():
        url = form.url.data
        wordlist = form.wordlist.data 
        if not re.match(r'^(http|https)://', url):
            flash('Invalid URL. Please enter a valid URL.', 'danger')
        else:
            alert_enabled = form.alert_enabled.data
            new_scan = WebPathScan(url=url, user_id=current_user.id, status='waiting', wordlist=wordlist, alert_enabled=alert_enabled, timestamp=datetime.utcnow())
            db.session.add(new_scan)
            db.session.commit()

            process_queue(new_scan)

            flash('Web path scan started!', 'success')
            return redirect(url_for('webpathscan.webpathscan'))

    user_scans = WebPathScan.query.filter_by(user_id=current_user.id).order_by(WebPathScan.timestamp.desc()).all()
    return render_template('webpathscan.html', form=form, scans=user_scans)

@bp.route('/view_webpathscan/<uuid:scan_id>')
@login_required
def view_webpathscan(scan_id):
    from app.models import WebPathScan
    import json
    logger.debug(f"Fetching scan with id: {scan_id}")

    scan = WebPathScan.query.get_or_404(scan_id)
    logger.debug(f"Scan fetched: {scan}")

    scan_result = json.loads(scan.result) if scan.result else []
    return render_template('view_webpathscan.html', scan=scan, scan_result=scan_result)

@bp.route('/rescan_webpath/<uuid:scan_id>', methods=['POST'])
@login_required
@csrf.exempt
def rescan_webpath(scan_id):
    from app.models import WebPathScan

    scan = WebPathScan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('webpathscan.webpathscan'))

    if WebPathScan.query.filter_by(user_id=current_user.id, status='in progress').count() < MAX_CONCURRENT_SCANS:
        scan.status = 'waiting'
        db.session.commit()
        socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
        process_queue(scan)
        flash('Rescan started.', 'success')
    else:
        flash('You have reached the limit of simultaneous scans.', 'danger')

    return redirect(url_for('webpathscan.webpathscan'))

@bp.route('/cancel_webpath/<uuid:scan_id>', methods=['POST'])
@login_required
def cancel_webpath(scan_id):
    from app.models import WebPathScan

    scan = WebPathScan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
    elif scan.status == 'waiting':
        scan.status = 'cancelled'
        db.session.commit()
        socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
        flash('Scan canceled successfully.', 'success')
    else:
        flash('It is not possible to cancel this scan at this time.', 'danger')

    return redirect(url_for('webpathscan.webpathscan'))
