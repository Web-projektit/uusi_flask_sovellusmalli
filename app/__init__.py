from flask import Flask
from flask_bootstrap import Bootstrap
# from flask_fontawesome import FontAwesome
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import config
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS

bootstrap = Bootstrap()
# fa = FontAwesome()
mail = Mail()
moment = Moment()
db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
csrf = CSRFProtect()    

def create_app(config_name):
    app = Flask(__name__)
    CORS(app, supports_credentials=True, expose_headers=["Content-Type", "X-CSRFToken", "Authorization"])
   
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    # fa.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app) 

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .restapi import restapi as restapi_blueprint
    app.register_blueprint(restapi_blueprint, url_prefix='/restapi')


    return app
