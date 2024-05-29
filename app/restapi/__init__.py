from flask import Blueprint
from flask_cors import CORS

restapi = Blueprint('restapi', __name__)
CORS(restapi, supports_credentials=True, expose_headers=["Content-Type", "X-CSRFToken", "Authorization"])

from . import views



