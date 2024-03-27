import sys
import logging
from datetime import datetime,timezone
from threading import Thread
from flask import current_app, render_template
from flask_mail import Message
from . import mail

def send_async_email(app, msg):
    logging.basicConfig(filename='application.log', level=logging.INFO)
    with app.app_context():
        # mail.send(msg)
        try:
            mail.send(msg)
            sys.stderr.write('Sahkoposti lahetetty\n')
            logging.info('Sähköposti lähetetty')
        except Exception as e:
            e_name = e.__class__.__name__
            sys.stderr.write('Sahkopostilahetysvirhe: ' + e_name + '\n')
            sys.stderr.write(str(e) + '\n')  
            logging.error(str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + ' sähköpostilähetysvirhe: ' + e_name)
            logging.error(str(e))   

def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    msg = Message(app.config['SOVELLUSMALLI_MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['SOVELLUSMALLI_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
