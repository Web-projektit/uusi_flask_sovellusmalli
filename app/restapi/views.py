import sys
from flask import render_template, redirect, current_app, request, g, jsonify, url_for, flash, make_response
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import restapi
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, ChangePasswordForm,\
    PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm
from .authentication import auth
from flask_wtf.csrf import generate_csrf,CSRFError
from urllib.parse import urlencode
from itsdangerous import URLSafeTimedSerializer as Serializer

def getUser():
    return current_user

def createResponse(message):
    # CORS:n vaatimat Headerit
    default_origin = 'http://localhost:3000'
    origin = request.headers.get('Origin',default_origin)
    response = make_response(jsonify(message))  
    # Määritetään CORS-alustuksessa
    # response.headers.set('Access-Control-Allow-Credentials','true')
    # Jos vaaditaan muuta kuin CORS-alustuksen '*'
    response.headers.set('Access-Control-Allow-Origin',origin) 
    return response


@restapi.app_errorhandler(CSRFError)
def handle_csrf_error(e):
    response = {'virhe':f'csrf-token puuttuu ({e.description}), headers:{str(request.headers)}'}
    # print(f"\nPRINT:reactapi CSFRError,SIGNIN headers:{str(request.headers)}\n")
    sys.stderr.write(f"\nreactapi CSFRError,headers:{str(request.headers)}\n")
    return createResponse(response)


'''
@restapi.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint \
                and request.blueprint != 'auth' \
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))
'''

@restapi.route("/getcsrf", methods=["GET"])
# Määritetään CORS-alustuksessa
# @cross_origin(supports_credentials=True)
def get_csrf():
    token = generate_csrf()
    response = jsonify({"detail": "CSRF cookie set"})
    # Määritetään CORS-alustuksessa
    # response.headers.set('Access-Control-Expose-Headers','X-CSRFToken') 
    response.headers.set("X-CSRFToken", token)
    return response

@restapi.route('/unconfirmed')
def unconfirmed():
    app = current_app._get_current_object()
    app.logger.debug('reactapi.unconfirmed,endnode: %s',request.endpoint)
    if current_user.is_anonymous or current_user.confirmed:
        app.logger.debug('reactapi.unconfirmed,redirect: %s',current_user.is_anonymous)
        return redirect(app.config['REACT_ORIGIN'])
    return redirect(app.config['REACT_UNCONFIRMED'])

@restapi.route('/login', methods=['GET', 'POST'])
def login():
    data = request.get_json()
    if data is not None:
        form = LoginForm(data=data)
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data.lower()).first()
            # user = None
            if user is not None and user.verify_password(form.password.data):
                # login_user(user, form.remember_me.data)
                next = request.args.get('next')
                sys.stderr.write(f"\nrestapi,views.py,SIGNIN:OK, next:{next}, confirmed:{user.confirmed}\n")
                if next is None or not next.startswith('/'):
                    token = user.generate_auth_token()
                    if user.confirmed:
                        response = jsonify({'ok': True, 'confirmed': '1'})
                    else:
                        response = jsonify({'ok': True})
                    response.headers['Authorization'] = 'Bearer ' + token
                    return response
                return redirect(next)
            else:
                # Tässä kirjoitetaan virhelokiin epäonnistunut kysely
                query = str(User.query.filter_by(email=form.email.data.lower()).first())
                sys.stderr.write(f"\nviews.py,SIGNIN, query:{query}\n")
                response = jsonify({'virhe':'Väärät tunnukset'})
                # response.status_code = 200
                return response 
        else:
            print("validointivirheet:"+str(form.errors))
            response = jsonify(form.errors)
            return response
    return jsonify({'message': 'No data provided'}), 400

@restapi.route('/logout')
@auth.login_required
def logout():
    return jsonify({'message': 'You have been logged out.'})

@restapi.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if data is not None:
        form = RegistrationForm(data=data)
        if form.validate_on_submit():
            # Lyhyempi tapa tallentaa uusi käyttäjä tietokantaan
            user = User()
            form.email.data = form.email.data.lower()
            form.populate_obj(user)
            db.session.add(user)
            db.session.commit()
            token = user.generate_confirmation_token()
            send_email(user.email, 'Confirm Your Account',
                    'restapi/email/confirm', user=user, token=token)
            return jsonify({'message': 'OK'}), 201
        else:
            return jsonify({'message': 'Invalid data', 'errors': form.errors})
    return jsonify({'message': 'No data provided'}), 400


@restapi.route('/confirm/<token>')
# http://localhost:5000/restapi/confirm/eyJjb25maXJtIjozNX0.ZjTmeA.Z8LgLyLnBs0leoLTyGv2P1y1xGo
# CORS määritetään alustuksessa tai tässä
# @cross_origin(supports_credentials=True)
# @auth.login_required
# Huom. login_required vie login-sivulle, ja kirjautuminen takaisin tänne
def confirm(token):
    app = current_app._get_current_object()
    referer = request.headers.get('Referer')
    # app.logger.debug('/confirm,confirmed: %s',current_user.confirmed)
    app.logger.debug('/confirm,headers:' + str(request.headers))
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except:
        message = 'Vahvistuslinkki on virheellinen tai se ei ole enää voimassa.'
        if referer is not None:
            return jsonify({'ok':"Virhe",'message':message, 'referer':referer})
        else:
            encoded_params = urlencode({ 'message':message })
            return redirect(app.config['REACT_UNCONFIRMED'] + "?" + encoded_params) 
    current_user = User.query.get(data.get('confirm'))
    if current_user is None:
        message = 'Käyttäjää ei löydy.'
        if referer is not None:
            return jsonify({'ok':'virhe','message': message}), 404
        else:
            encoded_params = urlencode({ 'message':message })
            return redirect(app.config['REACT_UNCONFIRMED'] + "?" + encoded_params) 
    elif current_user.confirmed:
        # Huom. Tähän vain sähköpostilinkistä kirjautuneena.
        # Siirtyminen uuteen ikkunaan ei-kirjautuneena
        # Huom. Nyt sama ilmoitus kuin ensi kertaa vahvistuksessa.
        app.logger.debug('/confirm,REACT_CONFIRMED:' + app.config['REACT_CONFIRMED'])
        return redirect(app.config['REACT_CONFIRMED'] + '?jo=jo')
        # message = "Sähköpostiosoite on jo vahvistettu."
        # return jsonify({'ok':"Virhe",'message':message})
    elif current_user.confirm(token):
        app.logger.debug('/confirm,confirmed here')
        db.session.commit()
        message = "Sähköpostiosoite on vahvistettu."
        # redirect_url = f"{app.config['REACT_ORIGIN']}?message={message}"
        # return redirect(redirect_url)
        if referer is not None:
            # Kirjautumisen kautta
            return jsonify({'ok':"OK",'message':message, 'confirmed':'1', 'referer':referer})
        else:
            # Sähköpostilinkin kautta suoraan
            app.logger.debug('\n/confirm,REACT_CONFIRMED:' + app.config['REACT_CONFIRMED']+'\n')
            return redirect(app.config['REACT_CONFIRMED'])
    else:
        # Huom. Kun on jo kirjauduttu toisella välilehdellä, Referer-headeriä ei ole.
        # Suojattu reitti /unfirmed Reactissa johtaa sinne kirjautumisen kautta. 
        message = 'Vahvistuslinkki on virheellinen tai se ei ole enää voimassa.'
        # redirect_url = f"{app.config['REACT_UNCONFIRMED']}?message={message}"
        # return redirect(redirect_url)
        # return jsonify({'ok':"Virhe",'message':message})
        if referer is not None:
            # Kirjautumisen kautta
            return jsonify({'ok':"Virhe",'message':message, 'referer':referer})
        else:
            encoded_params = urlencode({ 'message':message })
            return redirect(app.config['REACT_UNCONFIRMED'] + "?" + encoded_params) 
    # return redirect(app.config['REACT_ORIGIN'])

@restapi.route('/confirm')
# Huom. testattava, miten before_request sallii pääsyn tänne
@auth.login_required
def resend_confirmation():
    token = g.current_user.generate_confirmation_token()
    send_email(g.current_user.email, 'Confirm Your Account',
              'restapi/email/confirm', user=g.current_user, token=token)
    message = 'A new confirmation email has been sent to you by email.'
    return jsonify({'ok':"OK",'message':message})


@restapi.route('/change-password', methods=['GET', 'POST'])
@auth.login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password.')
    return render_template("auth/change_password.html", form=form)


@restapi.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    data = request.get_json()
    form = PasswordResetRequestForm(data=data)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'restapi/email/reset_password',
                       user=user, token=token, utm_source='email')
            message = 'An email with instructions to reset your password has been sent to you.'
            return jsonify({'ok':True,'message':message})
        return jsonify({'virhe': 'Käyttäjää ei löytynyt'})
    return jsonify({'virhe': 'Invalid data', 'errors': form.errors})


@restapi.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    app = current_app._get_current_object()
    referer = request.args.get('utm_source')
    app.logger.debug('/password_reset,headers:' + str(request.headers))
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except:
        message = 'Salasanan uusimislinkki on virheellinen tai se ei ole enää voimassa.'
        if referer is not 'email':
            return jsonify({'ok':"Virhe",'message':message, 'referer':referer})
        else:
            encoded_params = urlencode({ 'message':message })
            return redirect(app.config['REACT_RESET_PASSWORD'] + "?" + encoded_params) 
    current_user = User.query.get(data.get('reset'))
    if current_user is None:
        message = 'Käyttäjää ei löydy.'
        if referer is not 'email':
            return jsonify({'ok':False,'virhe':True,'message': message}), 404
        else:
            encoded_params = urlencode({ 'token':token,'message':message })
            return redirect(app.config['REACT_RESET_PASSWORD'] + "?" + encoded_params) 
    else:
        # Huom. Tähän vain sähköpostilinkistä kirjautuneena.
        app.logger.debug('/reset,REACT_RESET_PASSWORD:' + app.config['REACT_RESET_PASSWORD'])
        encoded_params = urlencode({ 'token':token })
        return redirect(app.config['REACT_RESET_PASSWORD'] + '?' + encoded_params)
    
@restapi.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    data = request.get_json()
    form = PasswordResetForm(data=data)
    if form.validate_on_submit():
        if User.reset_password(token, form.password.data):
            db.session.commit()
            message = 'Your password has been updated.'
            return jsonify({'ok':True,'virhe':message,'message': message})
        else:
            return jsonify({'ok':False,'virhe':'Käyttäjää ei löydy tai uusimislinkki on vanhentunut.','message': 'Käyttäjää ei löydy.'})
    return jsonify({'ok':False,'virhe':'Invalid data','message': 'Invalid data', 'errors': form.errors})

@restapi.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data.lower()
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, 'Confirm your email address',
                       'auth/email/change_email',
                       user=current_user, token=token)
            flash('An email with instructions to confirm your new email '
                  'address has been sent to you.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password.')
    return render_template("auth/change_email.html", form=form)


@restapi.route('/change_email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        db.session.commit()
        flash('Your email address has been updated.')
    else:
        flash('Invalid request.')
    return redirect(url_for('main.index'))
