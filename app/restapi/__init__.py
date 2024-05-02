from flask import Blueprint

restapi = Blueprint('restapi', __name__)

from . import views



