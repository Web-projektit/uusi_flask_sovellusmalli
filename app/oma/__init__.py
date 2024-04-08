from flask import Blueprint

oma = Blueprint('oma', __name__)

from . import views

