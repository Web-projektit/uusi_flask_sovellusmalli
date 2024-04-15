from flask import render_template
from sqlalchemy.exc import OperationalError
from . import main
import logging

logger = logging.getLogger(__name__)

@main.app_errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@main.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@main.app_errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@main.app_errorhandler(OperationalError)
def handle_operational_error(e):
    logger.error(f"Database operation failed: {e}")
    error_code = e.code
    if error_code == 'e3q8':
        error_message = "Tietokantayhteys ei toimi. Yritä myöhemmin uudelleen."
    else:
        error_message = str(e)
    return render_template('OperationalError.html', error_code=error_code, error_message=error_message)
