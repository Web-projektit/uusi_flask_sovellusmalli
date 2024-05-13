from flask import current_app, g, request, jsonify, redirect, url_for
from flask_httpauth import HTTPTokenAuth
from ..models import User
from . import restapi
from .errors import unauthorized, forbidden
from urllib.parse import urlencode


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
    app = current_app._get_current_object()
    # Huom. Tarve saattaa olla uudelleen ohjaus kirjautumissivulle.
    authorization_header = request.headers.get('Authorization')
    app.logger.debug(f"auth_error, request.endpoint:{request.endpoint},request.referrer:{request.referrer},authorization_header:{authorization_header}")
       # return unauthorized('Invalid credentials')
    if request.referrer is None:
        all_params = request.args.to_dict()
        route = url_for(request.endpoint, **all_params)
        route = route.split('/')[-1]
        next = '?next=' + route if route != '' else ''
        redirectUrl = app.config['REACT_LOGIN'] + next
        app.logger.debug(f"url:{redirectUrl},route:{route},next:{next}")
        return redirect(app.config['REACT_LOGIN'] + next)
    else:
        return unauthorized('Invalid credentials')

@restapi.before_request
# @auth.login_required
def before_request():
    # Huom. pääsyä vahvistamiseen ei saa estää.
    print("before_request, request.endpoint:",request.endpoint,"request.referrer:",request.referrer)
    print("before_request, utm_source:",request.args.get('utm_source'))
    if hasattr(g, 'current_user') and \
        not g.current_user.is_anonymous and \
        not g.current_user.confirmed:
        return forbidden('Unconfirmed account')


@restapi.route('/tokens/', methods=['POST'])
def get_token():
    if g.current_user.is_anonymous or g.token_used:
        return unauthorized('Invalid credentials')
    return jsonify({'token': g.current_user.generate_auth_token(), 'expiration': expiration})
