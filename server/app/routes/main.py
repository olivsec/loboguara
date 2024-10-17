from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from app import db, bcrypt
from app.models import Keyword, MonitoredCertificate
from app.forms import KeywordForm, DeleteForm, SearchLeakedDataForm, UpdateEmailForm, UpdatePasswordForm, UpdateTimezoneForm
from flask_login import login_required, current_user
from flask_wtf.csrf import generate_csrf
from flask_bcrypt import Bcrypt
from flask import current_app as app
import requests

bp = Blueprint('main', __name__)

bcrypt = Bcrypt()

@bp.route('/')
@login_required
def index():
    return redirect(url_for('main.about'))

@bp.route('/sslcertificatesearch', methods=['GET'])
@login_required
def certificates():
    query = request.args.get('query')
    total_records = request.args.get('total_records', type=int, default=10)

    if query is not None:
        if len(query) > 4:
            try:

                api_token = current_app.config.get('API_ACCESS_TOKEN')
                if not api_token:
                    return jsonify({"error": "API token is missing in configuration."}), 500


                api_url = current_app.config.get('API_URL') + "/certificate_search"
                headers = {
                    'x-access-tokens': api_token
                }
                params = {
                    'query': query,
                    'total_records': total_records
                }
                response = requests.get(api_url, headers=headers, params=params)

                if response.status_code == 200:
                    certs = response.json()
                    current_app.logger.info(f"Query: {query}, Total Records: {total_records}, Results: {len(certs)} records found")
                    return jsonify(certs)
                else:
                    current_app.logger.error(f"Failed to fetch certificates from API: {response.text}")
                    return jsonify({"error": "Failed to fetch certificates from API"}), 500
            except Exception as e:
                current_app.logger.error(f"Error during API request: {e}")
                return jsonify({"error": "An error occurred while fetching certificates."}), 500
        else:
            return jsonify({"error": "Query must be longer than 4 characters."}), 400
    else:

        return render_template('certificates.html', certs=None, query=query)



@bp.route('/sslcertificatediscovery', methods=['GET', 'POST'])
@login_required
def monitor():
    import time
    start_time = time.time()
    
    keyword_form = KeywordForm()
    delete_form = DeleteForm()
    
    if keyword_form.validate_on_submit():
        keyword = keyword_form.keyword.data
        if keyword and len(keyword) >= 4:
            new_keyword = Keyword(user_id=current_user.id, keyword=keyword)
            db.session.add(new_keyword)
            db.session.commit()
            flash('Keyword added successfully!', 'success')
            return redirect(url_for('main.monitor'))
        else:
            flash('Keyword must be at least 4 characters long.', 'danger')

    start_query_time = time.time()
    keywords = Keyword.query.filter_by(user_id=current_user.id).order_by(Keyword.id.desc()).limit(10).all()
    query_time = time.time() - start_query_time
    current_app.logger.info(f"Keyword query took {query_time:.4f} seconds")

    show_load_more_keywords = len(keywords) == 10


    start_query_time = time.time()
    monitored_certs = MonitoredCertificate.query.filter_by(user_id=current_user.id).order_by(MonitoredCertificate.timestamp.desc()).limit(10).all()
    query_time = time.time() - start_query_time
    current_app.logger.info(f"Certificate query took {query_time:.4f} seconds")

    show_load_more_certs = len(monitored_certs) == 10

    end_time = time.time()
    current_app.logger.info(f"Monitor route took {end_time - start_time:.4f} seconds to execute")

    return render_template('monitor.html', keyword_form=keyword_form, delete_form=delete_form, keywords=keywords, monitored_certs=monitored_certs, show_load_more_keywords=show_load_more_keywords, show_load_more_certs=show_load_more_certs)

@bp.route('/about')
@login_required
def about():
    return render_template('about.html')

@bp.route('/dataleak/dataleakalerts')
@login_required
def data_leaks():
    query = request.args.get('query')
    per_page = 12

    api_token = current_app.config.get('API_ACCESS_TOKEN')
    api_url = current_app.config.get('API_URL') + "/data_leak_alerts"
    headers = {
        'x-access-tokens': api_token
    }
    params = {'query': query, 'limit': per_page}
    response = requests.get(api_url, headers=headers, params=params)

    if response.status_code == 200:
        cleaned_alerts = response.json()['items']
        show_load_more = response.json()['has_more']
    else:
        cleaned_alerts = []
        show_load_more = False

    return render_template('data_leaks.html', alerts=cleaned_alerts, show_load_more=show_load_more, query=query)

@bp.route('/threatintelfeeds')
@login_required
def threat_intel_feeds():
    query = request.args.get('query')
    per_page = 12

    api_token = current_app.config.get('API_ACCESS_TOKEN')
    api_url = current_app.config.get('API_URL') + "/threat_intel_feeds"
    headers = {
        'x-access-tokens': api_token
    }
    params = {'query': query, 'limit': per_page}
    response = requests.get(api_url, headers=headers, params=params)

    if response.status_code == 200:
        feeds = response.json()['items']
        show_load_more = response.json()['has_more']
    else:
        feeds = []
        show_load_more = False

    return render_template('threat_intel_feeds.html', feeds=feeds, show_load_more=show_load_more, query=query)

@bp.route('/dataleak/urluserpass', methods=['GET'])
@login_required
def url_user_pass():
    form = SearchLeakedDataForm(request.args)
    query = form.query.data
    field = form.field.data
    limit = request.args.get('limit', type=int, default=10)

    api_token = current_app.config.get('API_ACCESS_TOKEN')
    api_url = current_app.config.get('API_URL') + "/url_user_pass"
    headers = {
        'x-access-tokens': api_token
    }
    params = {'query': query, 'field': field, 'limit': limit}
    response = requests.get(api_url, headers=headers, params=params)

    if response.status_code == 200:
        results = response.json()['items']
        show_load_more = response.json()['has_more']
    else:
        results = []
        show_load_more = False

    return render_template('url_user_pass.html', form=form, results=results, query=query, field=field, show_load_more=show_load_more, limit=limit)


@bp.route('/add_keyword', methods=['POST'])
@login_required
def add_keyword():
    form = KeywordForm()
    if form.validate_on_submit():
        keyword = form.keyword.data
        if keyword and len(keyword) >= 4:
            new_keyword = Keyword(user_id=current_user.id, keyword=keyword)
            db.session.add(new_keyword)
            db.session.commit()
            flash('Keyword added successfully!', 'success')
        else:
            flash('Keyword must be at least 4 characters long.', 'danger')
    return redirect(url_for('main.monitor'))

@bp.route('/delete_keyword/<int:keyword_id>', methods=['POST'])
@login_required
def delete_keyword(keyword_id):
    keyword = Keyword.query.get(keyword_id)
    if keyword and keyword.user_id == current_user.id:
        if 'remove_certificates' in request.form and request.form['remove_certificates']:
            monitored_cert_ids = db.session.query(MonitoredCertificate.id).filter(
                MonitoredCertificate.user_id == current_user.id,
                MonitoredCertificate.domain.ilike(f"%{keyword.keyword}%")
            ).all()
            for cert_id in monitored_cert_ids:
                cert = MonitoredCertificate.query.get(cert_id)
                if cert:
                    db.session.delete(cert)

        db.session.delete(keyword)
        db.session.commit()
        flash('Keyword and associated certificates deleted successfully!', 'success')
    else:
        flash('Keyword not found or not authorized.', 'danger')
    return redirect(url_for('main.monitor'))

@bp.route('/delete_monitored_certificate/<int:cert_id>', methods=['POST'])
@login_required
def delete_monitored_certificate(cert_id):
    cert = MonitoredCertificate.query.get(cert_id)
    if cert:
        if cert.user_id == current_user.id:
            db.session.delete(cert)
            db.session.commit()
            flash('Monitored certificate deleted successfully!', 'success')
        else:
            flash('Not authorized to delete this certificate.', 'danger')
            app.logger.info(f"User {current_user.id} is not authorized to delete certificate {cert_id}")
    else:
        flash('Monitored certificate not found.', 'danger')
        app.logger.info(f"Certificate with ID {cert_id} not found.")
        
    return redirect(url_for('main.monitor'))

@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    email_form = UpdateEmailForm()
    password_form = UpdatePasswordForm()
    timezone_form = UpdateTimezoneForm()

    if email_form.submit.data and email_form.validate_on_submit():
        current_user.email = email_form.email.data
        db.session.commit()
        flash('Your email has been updated!', 'success')
        return redirect(url_for('main.profile'))

    if password_form.submit.data and password_form.validate_on_submit():
        current_user.password = bcrypt.generate_password_hash(password_form.password.data).decode('utf-8')
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('main.profile'))

    if timezone_form.submit_timezone.data and timezone_form.validate_on_submit():
        if timezone_form.timezone.data:
            current_user.idtimezone = timezone_form.timezone.data
        db.session.commit()
        flash('Your timezone has been updated!', 'success')
        return redirect(url_for('main.profile'))

    if request.method == 'GET':
        email_form.email.data = current_user.email
        timezone_form.timezone.data = current_user.idtimezone if current_user.idtimezone is not None else 1

    return render_template('profile.html', 
                           email_form=email_form, 
                           password_form=password_form, 
                           timezone_form=timezone_form)

@bp.route('/load_more', methods=['GET'])
@login_required
def load_more():
    last_id = request.args.get('last_id', type=int)
    last_timestamp = request.args.get('last_timestamp')
    data_type = request.args.get('type')
    query = request.args.get('query', '')
    field = request.args.get('field', '')
    limit = request.args.get('limit', type=int, default=10)

    if data_type == 'certificates':
        monitored_certs_query = MonitoredCertificate.query.filter_by(user_id=current_user.id)

        if last_id:
            monitored_certs_query = monitored_certs_query.filter(MonitoredCertificate.id < last_id)
        
        monitored_certs = monitored_certs_query.order_by(MonitoredCertificate.timestamp.desc()).limit(limit).all()

        items = [{
            'id': cert.id,
            'domain': cert.domain,
            'timestamp': cert.timestamp.isoformat(),
            'csrf_token': generate_csrf()
        } for cert in monitored_certs]

        has_more = len(monitored_certs) == limit
        last_id = items[-1]['id'] if has_more else None
        last_timestamp = items[-1]['timestamp'] if has_more else None

        return jsonify({'items': items, 'has_more': has_more, 'last_id': last_id, 'last_timestamp': last_timestamp})


    api_token = current_app.config.get('API_ACCESS_TOKEN')
    headers = {
        'x-access-tokens': api_token
    }

    if data_type == 'alerts':
        api_url = current_app.config.get('API_URL') + "/data_leak_alerts"
    elif data_type == 'feeds':
        api_url = current_app.config.get('API_URL') + "/threat_intel_feeds"
    elif data_type == 'url_user_pass':
        api_url = current_app.config.get('API_URL') + "/url_user_pass"
    else:
        return jsonify({"error": "Invalid data type."}), 400

    params = {
        'query': query,
        'field': field,
        'limit': limit,
        'last_id': last_id,
        'last_timestamp': last_timestamp
    }

    response = requests.get(api_url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return jsonify({
            'items': data['items'],
            'has_more': data['has_more'],
            'last_id': data.get('last_id'),
            'last_timestamp': data.get('last_timestamp')
        })
    else:
        current_app.logger.error(f"Failed to load more data from API: {response.text}")
        return jsonify({"error": "Failed to load more data from API"}), 500
