from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User

errorMessages = {'dataRequired':"Anna {field}"}
class CustomDataRequired(DataRequired):
    def __init__(self, fieldname):
        super().__init__(message=errorMessages['dataRequired'].replace("{field}", fieldname))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[CustomDataRequired('sähköpostiosoite'), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Muista minut')
    submit = SubmitField('Kirjaudu')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[CustomDataRequired('sähköpostiosoite'), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'Käytä vain kirjaimia, numeroita, pisteitä tai '
               'alaviivoja')])
    password = PasswordField('Password', validators=[
        CustomDataRequired('salasana'), EqualTo('password2', message='Salasanat eivät täsmää')])
    password2 = PasswordField('Vahvista salasana', validators=[CustomDataRequired('salasana uudestaan')])
    submit = SubmitField('Rekisteröidy')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Sähköpostiosoite on varattu')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Käyttäjätunnus on varattu')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old password', validators=[CustomDataRequired('vanha salasana')])
    password = PasswordField('New password', validators=[
        CustomDataRequired('uusi salasana'), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Vahvista salasana',
                              validators=[CustomDataRequired('uusi salasana uudestaan')])
    submit = SubmitField('Vaihda salasana')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[CustomDataRequired('sähköpostiosoite'), Length(1, 64),
                                             Email()])
    submit = SubmitField('Lähetä salasanan uusimislinkki')


class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        CustomDataRequired('uusi salasana'), EqualTo('password2', message='Salasanat eivät täsmää')])
    password2 = PasswordField('Vahvista salasana', validators=[CustomDataRequired('uusi salasana uudestaan')])
    submit = SubmitField('Uusi salasana')


class ChangeEmailForm(FlaskForm):
    email = StringField('New Email', validators=[CustomDataRequired('uusi sähköpostiosoite'), Length(1, 64),
                                                 Email()])
    password = PasswordField('Password', validators=[CustomDataRequired('salasana')])
    submit = SubmitField('Vaihda sähköposti')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Sähköpostiosoite on varattu')
