from app import db, create_app  
from app.models import (
    DashboardMetrics, 
    DomainScan, 
    URLScan, 
    WebPathScan, 
    Keyword, 
    MonitoredCertificate, 
    RedirectionLink, 
    LinkAccess, 
    URLMonitoring
)
from sqlalchemy import func
from datetime import datetime

def update_dashboard_metrics():
    
    total_certificates_monitored = db.session.query(func.count(MonitoredCertificate.id)).scalar()
    top_keywords = db.session.query(Keyword.keyword, func.count(Keyword.id)).group_by(Keyword.keyword).order_by(func.count(Keyword.id).desc()).limit(5).all()
    top_keywords = {kw[0]: kw[1] for kw in top_keywords}
    
    total_tracking_links = db.session.query(func.count(RedirectionLink.id)).scalar()
    total_link_accesses = db.session.query(func.count(LinkAccess.id)).scalar()
    
    total_domain_scans = db.session.query(func.count(DomainScan.id)).scalar()
    top_domains_scanned = db.session.query(DomainScan.domain, func.count(DomainScan.id)).group_by(DomainScan.domain).order_by(func.count(DomainScan.id).desc()).limit(5).all()
    top_domains_scanned = {domain[0]: domain[1] for domain in top_domains_scanned}
    
    total_webpath_scans = db.session.query(func.count(WebPathScan.id)).scalar()
    top_uris_found = db.session.query(WebPathScan.url, func.count(WebPathScan.id)).group_by(WebPathScan.url).order_by(func.count(WebPathScan.id).desc()).limit(5).all()
    top_uris_found = {uri[0]: uri[1] for uri in top_uris_found}
    
    total_url_scans = db.session.query(func.count(URLScan.id)).scalar()
    public_url_scans = db.session.query(func.count(URLScan.id)).filter_by(is_public=True).scalar()
    
    total_url_monitorings = db.session.query(func.count(URLMonitoring.id)).scalar()
    activated_urls = db.session.query(func.count(URLMonitoring.id)).filter_by(status='completed').scalar()

    

    
    metrics = DashboardMetrics(
        timestamp=datetime.utcnow(),
        total_certificates_monitored=total_certificates_monitored,
        top_keywords=top_keywords,
        total_tracking_links=total_tracking_links,
        total_link_accesses=total_link_accesses,
        total_domain_scans=total_domain_scans,
        top_domains_scanned=top_domains_scanned,
        total_webpath_scans=total_webpath_scans,
        top_uris_found=top_uris_found,
        total_url_scans=total_url_scans,
        public_url_scans=public_url_scans,
        total_url_monitorings=total_url_monitorings,
        activated_urls=activated_urls,
        total_data_leak_alerts=0,  
        total_data_leak_credentials=0,  
        total_threat_intel_feeds=0,  
        top_threat_intel_sources={}  
    )

    
    db.session.query(DashboardMetrics).delete()

    
    db.session.add(metrics)
    db.session.commit()



if __name__ == "__main__":
    app = create_app()  
    with app.app_context():
        update_dashboard_metrics()
