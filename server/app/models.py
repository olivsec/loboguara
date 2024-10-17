from app import db
from flask_login import UserMixin
from datetime import datetime, timedelta
import uuid
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import configure_mappers
from sqlalchemy.ext.declarative import declarative_base
import random
import string

Base = declarative_base()

class Timezone(db.Model):
    __tablename__ = 'timezones'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    pytz_name = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Timezone {self.name}>'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    verification_code = db.Column(db.String(6), nullable=True)
    verification_code_expiration = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_superadmin = db.Column(db.Boolean, default=False)

    domainscans = db.relationship('DomainScan', back_populates='user', lazy=True, cascade='all, delete-orphan')
    urlscans = db.relationship('URLScan', back_populates='user', lazy=True, cascade='all, delete-orphan')
    webpathscans = db.relationship('WebPathScan', back_populates='user', lazy=True, cascade='all, delete-orphan')
    keywords = db.relationship('Keyword', back_populates='user', lazy=True, cascade='all, delete-orphan')
    monitored_certificates = db.relationship('MonitoredCertificate', back_populates='user', lazy=True, cascade='all, delete-orphan')
    redirection_links = db.relationship('RedirectionLink', back_populates='user', lazy=True, cascade='all, delete-orphan')
    urlmonitorings = db.relationship('URLMonitoring', back_populates='user', lazy=True, cascade='all, delete-orphan')

    idtimezone = db.Column(db.Integer, db.ForeignKey('timezones.id'), nullable=True)
    timezone = db.relationship('Timezone', backref='users')

class Keyword(db.Model):
    __tablename__ = 'keywords'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    keyword = db.Column(db.String(255), nullable=False)
    user = db.relationship('User', back_populates='keywords')

class MonitoredCertificate(db.Model):
    __tablename__ = 'monitored_certificates'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    certificate_id = db.Column(db.Integer, nullable=False)
    domain = db.Column(db.String(255), nullable=False) 
    timestamp = db.Column(db.DateTime, nullable=False)
    user = db.relationship('User', back_populates='monitored_certificates')

class DomainScan(db.Model):
    __tablename__ = 'domainscans'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    whois_result = db.Column(db.Text, nullable=True)
    subdomains = db.Column(db.JSON, nullable=True)
    additional_info = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alert_enabled = db.Column(db.Boolean, default=False)
    user = db.relationship('User', back_populates='domainscans')

class URLScan(db.Model):
    __tablename__ = 'urlscan'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = db.Column(db.String(2048), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    result = db.Column(db.JSON, nullable=True, default=list)
    screenshots = db.Column(db.JSON, nullable=True, default=list)
    alert_enabled = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    error_log = db.Column(db.Text, nullable=True)
    execution_time = db.Column(db.Integer, nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    html_report_path = db.Column(db.String(2048), nullable=True)
    headers_path = db.Column(db.String(2048), nullable=True)

    user = db.relationship('User', back_populates='urlscans')
    monitoring = db.relationship('URLMonitoring', back_populates='scan', uselist=False)

class WebPathScan(db.Model):
    __tablename__ = 'webpathscans'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = db.Column(db.String(2048), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    result = db.Column(db.Text, nullable=True)
    waf_detected = db.Column(db.Boolean, default=False)
    waf_name = db.Column(db.String(255), nullable=True)
    alert_enabled = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='webpathscans')
    wordlist = db.Column(db.String(255), nullable=False)

class RedirectionLink(db.Model):
    __tablename__ = 'redirection_links'
    id = db.Column(db.String(10), primary_key=True, default=lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=10)))
    original_url = db.Column(db.String(2048), nullable=False)
    generated_url = db.Column(db.String(2048), nullable=False, unique=True)
    expiration_time = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow() + timedelta(hours=24))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    user = db.relationship('User', back_populates='redirection_links')

    def is_expired(self):
        return datetime.utcnow() > self.expiration_time

class LinkAccess(db.Model):
    __tablename__ = 'link_accesses'
    id = db.Column(db.Integer, primary_key=True)
    access_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(512))
    referer = db.Column(db.String(2048))
    headers = db.Column(db.Text)
    link_id = db.Column(db.String, db.ForeignKey('redirection_links.id', ondelete='CASCADE'), nullable=False)
    redirection_link = db.relationship('RedirectionLink', backref=db.backref('accesses', lazy=True))

class URLMonitoring(db.Model):
    __tablename__ = 'urlmonitoring'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = db.Column(UUID(as_uuid=True), db.ForeignKey('urlscan.id', ondelete='CASCADE'), nullable=True)
    url = db.Column(db.String(2048), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='in monitoring')
    last_checked = db.Column(db.DateTime, nullable=True)
    scan_interval = db.Column(db.Integer, default=600)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='urlmonitorings')
    scan = db.relationship('URLScan', back_populates='monitoring', uselist=False)

    def mark_completed(self):
        self.status = 'completed'
        db.session.add(self)
        db.session.commit()

class DashboardMetrics(db.Model):
    __tablename__ = 'dashboard_metrics'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    total_certificates_monitored = db.Column(db.Integer, nullable=False)
    top_keywords = db.Column(db.JSON, nullable=True)
    
    total_tracking_links = db.Column(db.Integer, nullable=False)
    total_link_accesses = db.Column(db.Integer, nullable=False)
    
    total_domain_scans = db.Column(db.Integer, nullable=False)
    top_domains_scanned = db.Column(db.JSON, nullable=True)
    
    total_webpath_scans = db.Column(db.Integer, nullable=False)
    top_uris_found = db.Column(db.JSON, nullable=True)
    
    total_url_scans = db.Column(db.Integer, nullable=False)
    public_url_scans = db.Column(db.Integer, nullable=False)
    
    total_url_monitorings = db.Column(db.Integer, nullable=False)
    activated_urls = db.Column(db.Integer, nullable=False)
    
    total_data_leak_alerts = db.Column(db.Integer, nullable=False)
    total_data_leak_credentials = db.Column(db.Integer, nullable=False)
    
    total_threat_intel_feeds = db.Column(db.Integer, nullable=False)
    top_threat_intel_sources = db.Column(db.JSON, nullable=True)

configure_mappers()
