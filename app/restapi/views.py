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

def getUser(token_id=None):
    # Funktiolla voidaan hakea user suojatulla reitillä
    if token_id is not None:
        app = current_app._get_current_object()
        s = Serializer(app.config['SECRET_KEY'])
        try:
            token = token_id.get('token')
            id_kentta = token_id.get('id_kentta')
            data = s.loads(token)
            print(f"\ngetUser,data:{data}\n")
            token_user = User.query.get(data.get(id_kentta))
            return token_user
        except Exception as e:
            print(f"\ngetUser,Exception:{e}\n")
            return None
    return g.current_user

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
    message = f'csrf-token puuttuu ({e.description}), headers:{str(request.headers)}'
    response = {'status':'virhe','message':message}
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
    '''
    message = "CSRF-token on luotu"
    response = jsonify({"status":"ok",'message':message})
    '''
    response = make_response()
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
                # Huom. next-osoite ei saa olla ulkoinen. 
                # Tässä aiotulle sivulle siirrytään React-sovelluksessa,
                # joten next on tyhjä.       
                if next is None or not next.startswith('/'):
                    token = user.generate_auth_token()
                    message = 'Kirjautuminen onnistui'
                    if user.confirmed:
                        response = jsonify({'status':'ok','message':message,'confirmed':'1'})
                    else:
                        response = jsonify({'status':'ok','message':message})
                    response.headers['Authorization'] = 'Bearer ' + token
                    return response
                return redirect(next)
            else:
                # Tässä kirjoitetaan virhelokiin epäonnistunut kysely
                query = str(User.query.filter_by(email=form.email.data.lower()).first())
                sys.stderr.write(f"\nviews.py,SIGNIN, query:{query}\n")
                message = 'Väärät tunnukset'
                response = jsonify({'status':'virhe','message':message})
                # response.status_code = 200
                return response 
        else:
            print("validointivirheet:"+str(form.errors))
            response = jsonify({'status':'virhe','errors':form.errors})
            return response
    return jsonify({'status':'virhe','message':'Tiedot puuttuvat'}), 400

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
            linkki = url_for('restapi.confirm', token=token, utm_source='email', _external=True)
            send_email(user.email, \
                'Confirm Your Account', \
                'restapi/email/confirm', \
                linkki=linkki,user=user)
            return jsonify({'status':'ok','message':'Rekisteröityminen onnistui'}), 201
        else:
            return jsonify({'status':'virhe','message':'Virheellisiä tietoja','errors':form.errors})
    return jsonify({'status':'virhe','message':'Tiedot puuttuvat'}), 400


@restapi.route('/confirm/<token>')
# http://localhost:5000/restapi/confirm/eyJjb25maXJtIjozNX0.ZjTmeA.Z8LgLyLnBs0leoLTyGv2P1y1xGo
# CORS määritetään alustuksessa tai tässä
# @cross_origin(supports_credentials=True)
# @auth.login_required
# Huom. login_required vie login-sivulle, ja kirjautuminen takaisin tänne
def confirm(token):
    app = current_app._get_current_object()
    referer = request.args.get('utm_source')
    # referer = request.headers.get('Referer')
    # app.logger.debug('/confirm,confirmed: %s',current_user.confirmed)
    app.logger.debug('/confirm,headers:' + str(request.headers))
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except:
        message = 'Vahvistuslinkki on virheellinen tai se ei ole enää voimassa'
        if referer != 'email':
            return jsonify({'status':"virhe",'message':message, 'referer':referer})
        else:
            encoded_params = urlencode({ 'message':message })
            return redirect(app.config['REACT_UNCONFIRMED'] + "?" + encoded_params) 
    current_user = User.query.get(data.get('confirm'))
    if current_user is None:
        message = 'Käyttäjää ei löydy.'
        if referer is not None:
            return jsonify({'status':'virhe','message': message}), 404
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
        message = "Sähköpostiosoite on vahvistettu"
        # redirect_url = f"{app.config['REACT_ORIGIN']}?message={message}"
        # return redirect(redirect_url)
        if referer != 'email':
            # Kirjautumisen kautta
            return jsonify({'status':"ok",'message':message,'confirmed':'1','referer':referer})
        else:
            # Sähköpostilinkin kautta suoraan
            app.logger.debug('\n/confirm,REACT_CONFIRMED:' + app.config['REACT_CONFIRMED']+'\n')
            return redirect(app.config['REACT_CONFIRMED'])
    else:
        # Huom. Kun on jo kirjauduttu toisella välilehdellä, Referer-headeriä ei ole.
        # Suojattu reitti /unfirmed Reactissa johtaa sinne kirjautumisen kautta. 
        message = 'Vahvistuslinkki on virheellinen tai se ei ole enää voimassa'
        # redirect_url = f"{app.config['REACT_UNCONFIRMED']}?message={message}"
        # return redirect(redirect_url)
        # return jsonify({'ok':"Virhe",'message':message})
        if referer != 'email':
            # Kirjautumisen kautta
            return jsonify({'status':"virhe",'message':message, 'referer':referer})
        else:
            encoded_params = urlencode({ 'message':message })
            return redirect(app.config['REACT_UNCONFIRMED'] + "?" + encoded_params) 
    # return redirect(app.config['REACT_ORIGIN'])

@restapi.route('/confirm')
# Huom. testattava, miten before_request sallii pääsyn tänne
@auth.login_required
def resend_confirmation():
    user = getUser()
    token = user.generate_confirmation_token()
    linkki = url_for('restapi.confirm', token=token, utm_source='email', _external=True)
    send_email(user.email, \
        'Confirm Your Account', \
        'restapi/email/confirm', \
        linkki=linkki,user=user)
    message = 'Uusi vahvistuslinkki on lähetetty sähköpostissa.'
    return jsonify({'status':"ok",'message':message})


@restapi.route('/change-password', methods=['GET', 'POST'])
@auth.login_required
def change_password():
    user = getUser()
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if user.verify_password(form.old_password.data):
            user.password = form.password.data
            db.session.add(user)
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
            linkki = url_for('restapi.password_reset', token=token, utm_source='email', _external=True)
            send_email(user.email, \
                'Reset Your Password', \
                'restapi/email/reset_password', \
                linkki=linkki,user=user)
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
        if referer != 'email':
            return jsonify({'ok':"Virhe",'message':message, 'referer':referer})
        else:
            encoded_params = urlencode({ 'message':message })
            return redirect(app.config['REACT_RESET_PASSWORD'] + "?" + encoded_params) 
    current_user = User.query.get(data.get('reset'))
    if current_user is None:
        message = 'Käyttäjää ei löydy.'
        if referer != 'email':
            return jsonify({'ok':False,'virhe':True,'message': message}), 404
        else:
            encoded_params = urlencode({ 'token':token,'message':message })
            return redirect(app.config['REACT_RESET_PASSWORD'] + "?" + encoded_params) 
    else:
        # Huom. Tähän vain sähköpostilinkistä kirjautuneena.
        app.logger.debug('/reset,REACT_RESET_PASSWORD:' + app.config['REACT_RESET_PASSWORD'])
        encoded_params = urlencode({ 'token':token })
        return redirect(app.config['REACT_RESET_PASSWORD'] + '?' + encoded_params)
    
@restapi.route('/reset_password', methods=['GET', 'POST'])    
@restapi.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token=None):
    if token is None:
        return jsonify({'status':'virhe','message': 'Virheellinen linkki'})
    data = request.get_json()
    form = PasswordResetForm(data=data)
    if form.validate_on_submit():
        if User.reset_password(token, form.password.data):
            db.session.commit()
            message = 'Your password has been updated.'
            return jsonify({'status':'ok','message': message})
        else:
            return jsonify({'status':'virhe','message':'Käyttäjää ei löydy tai uusimislinkki on vanhentunut'})
    return jsonify({'status':'virhe','message': 'Virheelliset tiedot', 'errors': form.errors})


@restapi.route('/change_email', methods=['POST'])
@auth.login_required
def change_email_request():
    user = getUser()
    data = request.get_json()
    form = ChangeEmailForm(data=data)
    if form.validate_on_submit():
        if user.verify_password(form.password.data):
            new_email = form.email.data.lower()
            token = user.generate_email_change_token(new_email)
            # Huom. tässä on vältetty linkin koodaaminen uudestaan tässä ja templatissä.
            # Huom. request.endpoint olisi tässä 'restapi.change_email_request',
            # jolloin - koska token-parametria ei ole määritetty sen
            # URL-osoitteeseen - token tulee URL-parametriksi eikä URL:n osaksi,
            # toisin kuin change_mail-funktion tapauksessa.
            linkki = url_for('restapi.change_email', token=token, utm_source='email', _external=True)
            print(f"linkki:{linkki}")
            send_email(new_email, \
                'Confirm your email address', \
                'restapi/email/change_email', \
                user=user,linkki=linkki)
                # user=user, token=token, utm_source='email' )
            message = "Uuteen sähköpostiosoitteeseesi on lähetetty viesti, jonka \
                       linkistä voit vahvistaa sen."       
            return jsonify({'status':'ok','message': message})
        else:
            return jsonify({'status':'virhe','message':'Väärä sähköposti'})
    return jsonify({'status':'virhe','message': 'Virheelliset tiedot', 'errors': form.errors})


@restapi.route('/change_email/<token>',methods=['GET'])
#@auth.login_required
def change_email(token):
    app = current_app._get_current_object()
    user = getUser({ 'token':token,'id_kentta':'change_email'})
    if user is not None:
        if user.change_email(token):
            db.session.commit()
            status = 'ok'
            message = 'Sähköpostiosoitteesi on vaihdettu. Kirjaudu uudelleen.'  
        else:
            status = 'virhe'
            message = 'Sähköpostiosoitteen vaihto epäonnistui.'
        encoded_params = urlencode({ 'status':status,'message':message })
        return redirect(app.config['REACT_LOGIN'] + '?' + encoded_params)
    status = 'virhe'
    message = 'Väärä linkki'
    encoded_params = urlencode({ 'status':status,'message':message })
    return redirect(app.config['REACT_LOGIN'] + '?' + encoded_params)
    
