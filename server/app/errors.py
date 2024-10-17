from flask import render_template
from app import db
from flask_wtf.csrf import CSRFError
import sqlalchemy.exc

def register_error_handlers(app):
    @app.errorhandler(403)
    def forbidden_error(error):
        app.logger.warning(f"403 Forbidden: {error}")
        return render_template('403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.warning(f"404 Not Found: {error}")
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"500 Internal Server Error: {error}", exc_info=True)
        if db.session.is_active:
            db.session.rollback()
        return render_template('500.html'), 500

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        app.logger.warning(f"CSRF Error: {e.description}")
        return render_template('csrf_error.html', reason=e.description), 400

    @app.errorhandler(OSError)
    def handle_os_error(error):
        if error.errno == 24:
            app.logger.error("OSError: Too many open files", exc_info=True)
            return render_template('too_many_open_files.html'), 500
        app.logger.error(f"OSError: {error.strerror} (Errno: {error.errno})", exc_info=True)
        return render_template('500.html'), 500

    @app.errorhandler(sqlalchemy.exc.PendingRollbackError)
    def handle_pending_rollback_error(error):
        app.logger.error(f"PendingRollbackError: {error}", exc_info=True)
        if db.session.is_active:
            db.session.rollback()
        return render_template('500.html', error_message="An error occurred with the database transaction."), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        app.logger.error(f"Unexpected error: {str(error)}", exc_info=True)
        if db.session.is_active:
            db.session.rollback()
        return render_template('default_error.html', error_code=500, error_message="An unexpected error occurred."), 500