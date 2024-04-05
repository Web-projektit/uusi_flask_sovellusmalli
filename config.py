import os
from dotenv import load_dotenv
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in \
        ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    SOVELLUSMALLI_MAIL_SUBJECT_PREFIX = os.environ.get('SOVELLUSMALLI_MAIL_SUBJECT_PREFIX','[Sovellusmalli]')
    SOVELLUSMALLI_MAIL_SENDER = 'Sovellusmalli Admin <sovellusmalli@example.com>'
    SOVELLUSMALLI_ADMIN = os.environ.get('SOVELLUSMALLI_ADMIN')
    SOVELLUSMALLI_POSTS_PER_PAGE = 25
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    DB_USERNAME = os.environ.get('LOCAL_DB_USERNAME') or 'root'
    DB_PASSWORD = os.environ.get('LOCAL_DB_PASSWORD') or ''
    DB_NAME = os.environ.get('LOCAL_DB_NAME') or 'flask_sovellusmalli'
    DB_SERVER = os.environ.get('LOCAL_DB_SERVER') or 'localhost'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://' + DB_USERNAME + ':' + DB_PASSWORD + '@' + DB_SERVER + ':3306/' + DB_NAME
    WTF_CSRF_ENABLED = True
    #SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
    #    'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite://'


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
