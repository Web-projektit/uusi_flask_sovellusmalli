from flask import Blueprint
# from flask_cors import CORS

restapi = Blueprint('restapi', __name__)
# CORS(restapi, supports_credentials=True, expose_headers=["Content-Type", "X-CSRFToken", "Authorization"])
# Huom. ei haluttua vaikutusta eli Access-Control-Allow-Credentials:true-headerin lähetystä, 
# jos request ei sisällä evästeitä eikä http-tunnuksia.

from . import views



