from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User

class LoginForm(Form):
    email = StringField('Email', validators = [Required(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remeber_me = BooleanField('Keep me logged in')
    submit = SubmitField('Login In')

class RegistrationForm(Form):
    email = StringField('Email', validators = [Required(), Length(1,64), Email()])
    username = StringField('Username',validators = [Required(), Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                                                    'Usernames must have only letters, '
                                                                                    'numbers, dots, or underscores')])
    password = PasswordField('Password',validators = [Required()])
    password2 = PasswordField('Confirm Password',validators = [Required(),
                                                               EqualTo('password', message = 'Password mush match')])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')

class ChangePasswordForm(Form):
    oldpassword = PasswordField("Old Password", validators = [Required()])
    newpassword = PasswordField('New Password', validators = [Required()])
    newpassword2 = PasswordField('Confirm New Password', validators = [Required(),
                                                                       EqualTo('newpassword', message = 'Password mush match')])
    submit = SubmitField('Change')

class ResetPasswordRequestForm(Form):
    email = StringField('Email',validators = [Required(), Length(1, 64), Email()])
    submit = SubmitField('Submit')

class ResetPasswordForm(Form):
    email = StringField('Email',validators = [Required(), Length(1, 64), Email()])
    password = PasswordField('Password',validators = [Required()])
    password2 = PasswordField('Confirm Password', validators = [Required(),
                                                                EqualTo('password', message = 'Password mush match')])
    submit = SubmitField('submit')

class ChangeEmailForm(Form):
    email = StringField('Email',validators = [Required(), Length(1,64), Email()])
    newemail = StringField('New Email',validators = [Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators = [Required()])
    submit = SubmitField('submit')
