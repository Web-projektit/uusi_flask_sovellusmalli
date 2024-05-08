from flask import g, jsonify
from flask_httpauth import HTTPTokenAuth
from ..models import User
from . import restapi
from .errors import unauthorized, forbidden

expiration = 3600
auth = HTTPTokenAuth(scheme='Bearer')

@auth.verify_token
def verify_token(token):
    if token == '':
        return False
    g.current_user = User.verify_auth_token(token,expiration)
    return g.current_user is not None
    

@auth.error_handler
def auth_error():
    # Huom. Tarve saattaa olla uudelleen ohjaus kirjautumissivulle.
    print("auth_error")
    return unauthorized('Invalid credentials')


@restapi.before_request
# @auth.login_required
def before_request():
    # Huom. pääsyä vahvistamiseen ei saa estää.
    print("before_request")
    if hasattr(g, 'current_user') and \
        not g.current_user.is_anonymous and \
        not g.current_user.confirmed:
        return forbidden('Unconfirmed account')


@restapi.route('/tokens/', methods=['POST'])
def get_token():
    if g.current_user.is_anonymous or g.token_used:
        return unauthorized('Invalid credentials')
    return jsonify({'token': g.current_user.generate_auth_token(), 'expiration': expiration})
