import random
import string
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from datetime import datetime
from app import db, current_app
from app.models import RedirectionLink, LinkAccess
from app.forms import RedirectionForm

bp = Blueprint('redirection', __name__)

@bp.route('/redirection', methods=['GET', 'POST'])
@login_required
def create_redirection():
    form = RedirectionForm()
    form.domain.choices = [(domain, domain) for domain in current_app.config['ALLOWED_DOMAINS']]
    
    if form.validate_on_submit():
        original_url = form.original_url.data
        domain = form.domain.data
        generated_id = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        generated_url = f'https://{domain}/{generated_id}'
        
        new_link = RedirectionLink(
            id=generated_id,
            original_url=original_url,
            generated_url=generated_url,
            user_id=current_user.id
        )
        db.session.add(new_link)
        db.session.commit()
        
        flash('Tracking link generated successfully!', 'success')
        return redirect(url_for('redirection.create_redirection'))
    
    user_links = RedirectionLink.query.filter_by(user_id=current_user.id).all()
    return render_template('redirection.html', form=form, links=user_links, datetime=datetime)

@bp.route('/<string:link_id>', methods=['GET'])
def track_and_redirect(link_id):
    link = RedirectionLink.query.filter_by(id=link_id).first_or_404()

    if link.is_expired():
        flash('This link has expired.', 'danger')
        return redirect(url_for('redirection.create_redirection'))
    
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.remote_addr

    access = LinkAccess(
        ip_address=ip_address,
        user_agent=request.headers.get('User-Agent'),
        referer=request.headers.get('Referer'),
        headers=str(request.headers),
        link_id=link.id
    )
    
    db.session.add(access)
    db.session.commit()

    return redirect(link.original_url)


@bp.route('/redirection/results/<string:link_id>', methods=['GET'])
@login_required
def view_results(link_id):
    link = RedirectionLink.query.filter_by(id=link_id, user_id=current_user.id).first_or_404()
    accesses = LinkAccess.query.filter_by(link_id=link_id).all()
    return render_template('redirection_results.html', link=link, accesses=accesses)
