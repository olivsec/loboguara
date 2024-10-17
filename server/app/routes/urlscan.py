from flask import Blueprint, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from datetime import datetime
import os
import logging
import threading
import signal
from app import db, create_app, socketio
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import json
from bs4 import BeautifulSoup
import uuid
from flask_wtf.csrf import CSRFError, CSRFProtect
import re
import socket
from urllib.parse import urlparse
from apscheduler.schedulers.background import BackgroundScheduler
import httpx
from app.jobs.notificationjobs import send_email

csrf = CSRFProtect()
bp = Blueprint('urlscan', __name__, url_prefix='/scan')

MAX_CONCURRENT_SCANS = 3
scan_queue = []
scan_threads = []
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)

logger = logging.getLogger('flask.app')

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException

signal.signal(signal.SIGALRM, timeout_handler)


def create_directories(output_dir, url):
    parsed_url = urlparse(url)
    safe_url = f"{parsed_url.scheme}_{parsed_url.netloc.replace('.', '_')}_{uuid.uuid4().hex[:8]}"
    
    headers_dir = os.path.join(output_dir, 'headers')
    html_dir = os.path.join(output_dir, 'html')
    screenshots_dir = os.path.join(output_dir, 'screenshots')

    os.makedirs(headers_dir, exist_ok=True)
    os.makedirs(html_dir, exist_ok=True)
    os.makedirs(screenshots_dir, exist_ok=True)

    logger.info(f"Directories created: {headers_dir}, {html_dir}, {screenshots_dir}")
    return headers_dir, html_dir, screenshots_dir, safe_url


def save_headers(headers_dir, safe_url, headers):
    headers_path = os.path.join(headers_dir, f"{safe_url}.txt")
    with open(headers_path, 'w') as f:
        for key, value in headers.items():
            f.write(f"{key}: {value}\n")
    logger.info(f"Headers saved to: {headers_path}")
    return headers_path


def save_html(html_dir, safe_url, body):
    html_path = os.path.join(html_dir, f"{safe_url}.html")
    with open(html_path, 'w') as f:
        f.write(body)
    logger.info(f"HTML saved to: {html_path}")
    return html_path


def fetch_url_info(url, output_dir):
    try:
        logger.info(f"Fetching URL info: {url}")
        with httpx.Client(follow_redirects=True, timeout=10) as client:
            response = client.get(url)
            status_code = response.status_code
            headers = response.headers
            body = response.text  

            logger.info(f"Response status: {status_code}")

            headers_dir, html_dir, screenshots_dir, safe_url = create_directories(output_dir, url)

            headers_path = save_headers(headers_dir, safe_url, headers)
            html_path = save_html(html_dir, safe_url, body) 

            return {
                'url': url,
                'status': status_code,
                'headers': headers,
                'body': body,
                'headers_path': headers_path,
                'html_path': html_path,
                'screenshots_dir': screenshots_dir,
                'safe_url': safe_url
            }
    except httpx.RequestError as e:
        logger.error(f"Error fetching data from {url}: {e}")
        return None

def take_screenshot(url, screenshots_dir, safe_url):

    chromedriver = current_app.config['CHROME_DRIVER_PATH']
    googlechrome = current_app.config['GOOGLE_CHROME_PATH']
    selenium_screenshot_path = os.path.join(screenshots_dir, f"{safe_url}.png")
    
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280x1024")
    
    chrome_service = Service(chromedriver, log_path='chromedriver.log')
    options.binary_location = googlechrome
    
    driver = webdriver.Chrome(service=chrome_service, options=options)
    try:
        logger.info(f"Capturing screenshot of: {url}")
        driver.get(url)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
        driver.save_screenshot(selenium_screenshot_path)
        logger.info(f"Screenshot saved to: {selenium_screenshot_path}")
    except Exception as e:
        logger.error(f"Error capturing screenshot for {url} with exception: {e}")
    finally:
        driver.quit()

    return selenium_screenshot_path


def get_page_title(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.title.string if soup.title else ''


def resolve_ip(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else url.split('/')[0]
        addrs = socket.gethostbyname_ex(hostname)
        return addrs[2]  
    except Exception as e:
        logger.error(f"Error resolving IP for {url}: {e}")
        return []


def run_urlscan(scan, callback=None):
    app = create_app()
    with app.app_context():
        from app.models import User, URLScan, URLMonitoring
        from app import get_session 

        with get_session() as session:
            scan = session.merge(scan)
            logger.info(f"Starting scan for URL: {scan.url}, scan_id: {scan.id}")

            try:
                scan.status = 'in progress'
                session.add(scan)
                session.commit()
                socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
                logger.info(f"Scan {scan.id} updated to 'in progress'")

            except Exception as e:
                logger.error(f"Error updating scan {scan.id} to 'in progress': {e}")
                session.rollback()
                return

            url = scan.url
            base_dir = '/opt/loboguara/urlscan-files/'
            output_dir = os.path.join(base_dir, f'scan_{scan.id}')
            os.makedirs(output_dir, exist_ok=True)
            logger.info(f"Output directory created: {output_dir}")

            try:
                start_time = time.time()

                logger.info(f"Starting to fetch URL info for: {url}")
                url_info = fetch_url_info(url, output_dir)
                if url_info is None:
                    logger.error(f"Error fetching URL info for {url}")
                    scan.status = 'completed with error'
                    session.commit()
                    return
                logger.info(f"URL info successfully fetched for {url}")

                page_title = get_page_title(url_info['body'])

                logger.info(f"Starting screenshot capture for: {url}")
                selenium_screenshot_path = take_screenshot(url, url_info['screenshots_dir'], url_info['safe_url'])
                logger.info(f"Screenshot successfully captured for: {url}")

                ip_addrs = resolve_ip(url)

                end_time = time.time()
                execution_time = int(end_time - start_time)
                logger.info(f"Execution time for scan {scan.id}: {execution_time} seconds")

                headers_list = [{'name': k, 'value': v, 'decreasesSecurity': False, 'increasesSecurity': False}
                                for k, v in url_info['headers'].items()]

                result_data = [{
                    'url': url_info['url'],
                    'status': f"{url_info['status']} OK",
                    'hostname': urlparse(url_info['url']).hostname,
                    'addrs': ip_addrs,
                    'pageTitle': page_title,
                    'bodyPath': os.path.relpath(url_info['html_path'], base_dir),
                    'screenshotPath': os.path.relpath(selenium_screenshot_path, base_dir),
                    'headers': headers_list
                }]

                scan.result = json.dumps(result_data)
                scan.execution_time = execution_time
                scan.status = 'completed'

                try:
                    session.add(scan)
                    session.commit()
                    logger.info(f"Scan {scan.id} successfully completed and saved to the database.")

                    monitoring = session.query(URLMonitoring).filter_by(scan_id=scan.id).first()
                    if monitoring:
                        monitoring.status = 'completed'
                        session.add(monitoring)
                        session.commit()
                        logger.info(f"Monitoring {monitoring.id} updated to 'completed'.")
                    else:
                        logger.warning(f"No monitoring found for scan_id {scan.id}")

                    if callback:
                        callback(scan)

                except Exception as e:
                    logger.error(f"Error saving scan {scan.id} to the database: {e}")
                    session.rollback()

            except Exception as e:
                logger.error(f"Error executing scan for {url}: {e}")
                scan.status = 'completed with error'
                try:
                    session.commit()
                except Exception as e:
                    logger.error(f"Error saving error status for scan {scan.id}: {e}")
                    session.rollback()

                monitoring = session.query(URLMonitoring).filter_by(scan_id=scan.id).first()
                if monitoring:
                    monitoring.status = 'completed with error'
                    session.add(monitoring)
                    session.commit()
                    logger.info(f"Monitoring {monitoring.id} updated to 'completed with error'.")
                else:
                    logger.warning(f"No monitoring found for scan_id {scan.id}")

            if scan.alert_enabled:
                user = session.query(User).get(scan.user_id)
                send_email(user.email, 'Scan Complete', f'Scanning for URL {scan.url} has completed.')


def is_resolvable(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else url.split('/')[0]

    try:
        socket.gethostbyname(hostname)
        logger.info(f"Hostname resolved: {hostname}")
        return True
    except socket.error as e:
        logger.error(f"Error resolving hostname {hostname}: {e}")
        return False


def process_queue(scan=None):
    global scan_threads
    if scan:
        scan_queue.append(scan)
        logger.info(f"Scan added to queue: {scan.url}")

    while len(scan_threads) < MAX_CONCURRENT_SCANS and scan_queue:
        scan = scan_queue.pop(0)
        thread = threading.Thread(target=run_urlscan, args=(scan,))
        thread.start()
        scan_threads.append(thread)
        logger.info(f"Scan thread started for: {scan.url}")

    for thread in scan_threads:
        thread.join(timeout=0) 
        if not thread.is_alive():
            scan_threads.remove(thread)
            logger.info('Scan thread completed and removed')

    from app.models import URLScan
    waiting_scans = URLScan.query.filter_by(status='waiting').all()
    for waiting_scan in waiting_scans:
        if waiting_scan not in scan_queue:
            scan_queue.append(waiting_scan)
            logger.info(f"Waiting scan added to queue: {waiting_scan.url}")


@bp.route('/urlscan', methods=['GET', 'POST'])
@login_required
def urlscan():
    from app.forms import URLScanForm
    from app.models import URLScan

    form = URLScanForm()
    if form.validate_on_submit():
        url = form.url.data
        alert_enabled = form.alert_enabled.data

        logger.info(f"Form validated with URL: {url}")

        if not is_resolvable(url):
            flash('The domain name could not be resolved to an IP. Please enter a valid URL.', 'danger')
            return redirect(url_for('urlscan.urlscan'))

        if URLScan.query.filter_by(user_id=current_user.id, status='in progress').count() >= MAX_CONCURRENT_SCANS:
            flash('You have reached the limit of 3 simultaneous scans.', 'danger')
            return redirect(url_for('urlscan.urlscan'))

        new_scan = URLScan(
            id=uuid.uuid4(), 
            url=url, 
            user_id=current_user.id, 
            status='waiting', 
            alert_enabled=alert_enabled, 
            timestamp=datetime.utcnow()
        )

        try:
            db.session.add(new_scan)
            db.session.commit()
            logger.info(f"New scan created with ID: {new_scan.id}")
        except Exception as e:
            logger.error(f"Error saving new scan to the database: {e}")
            db.session.rollback()
            flash('Error starting the scan. Please try again later.', 'danger')
            return redirect(url_for('urlscan.urlscan'))

        process_queue(new_scan)

        flash('URL scan started!', 'success')
        return redirect(url_for('urlscan.urlscan'))

    user_scans = URLScan.query.filter_by(user_id=current_user.id).order_by(URLScan.timestamp.desc()).all()
    return render_template('urlscan.html', form=form, scans=user_scans)


@bp.route('/view_urlscan/<uuid:scan_id>')
@login_required
def view_urlscan(scan_id):
    from app.models import URLScan
    logger.debug(f"Fetching scan with id: {scan_id}")

    scan = URLScan.query.get_or_404(scan_id)
    logger.debug(f"Scan fetched: {scan}")
    return render_template('view_mu.html', scan=scan, public_view=False)


@bp.route('/public/view_urlscan/<uuid:scan_id>')
def public_view_urlscan(scan_id):
    from app.models import URLScan
    scan = URLScan.query.get_or_404(scan_id)

    if not scan.is_public:
        flash('Access to this result is restricted.', 'danger')
        return redirect(url_for('main.index'))
    
    if not scan.result:
        flash('No scan results found for this ID.', 'warning')
        return redirect(url_for('main.index'))


    return render_template('public_view_mu.html', scan=scan, public_view=True)


@bp.route('/make_public/<uuid:scan_id>', methods=['POST'])
@login_required
def make_public(scan_id):
    from app.models import URLScan
    scan = URLScan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('urlscan.urlscan'))
    scan.is_public = True
    db.session.commit()
    flash('The scan result is now public.', 'success')
    return redirect(url_for('urlscan.view_urlscan', scan_id=scan.id))


@bp.route('/remove_public/<uuid:scan_id>', methods=['POST'])
@login_required
def remove_public(scan_id):
    from app.models import URLScan
    scan = URLScan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('urlscan.urlscan'))
    scan.is_public = False
    db.session.commit()
    flash('Public access to the scan result has been removed.', 'success')
    return redirect(url_for('urlscan.view_urlscan', scan_id=scan.id))


scheduler = BackgroundScheduler()

@bp.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400


@bp.route('/rescan_url/<uuid:scan_id>', methods=['POST'])
@login_required
@csrf.exempt
def rescan_url(scan_id):
    from app.models import URLScan

    scan = URLScan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('urlscan.urlscan'))

    if URLScan.query.filter_by(user_id=current_user.id, status='in progress').count() < MAX_CONCURRENT_SCANS:
        scan.status = 'waiting'
        db.session.commit()
        socketio.emit('update', {'id': str(scan.id), 'status': scan.status})
        process_queue(scan)
        flash('Rescan started.', 'success')
    else:
        flash('You have reached the limit of 3 simultaneous scans.', 'danger')

    return redirect(url_for('urlscan.urlscan'))
