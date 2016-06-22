from flask import render_template, redirect, request, url_for, flash
from flask.ext.login import login_user, logout_user, login_required, current_user
from ..models import User
from . import auth
from .. import db
from .forms import LoginForm , RegistrationForm , ChangePasswordForm, ResetPasswordRequestForm, ResetPasswordForm,ChangeEmailForm
from ..email import send_email

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
            current_user.ping()
            if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.' \
                and request.endpoint != 'static':
                return redirect(url_for('auth.unconfirmed'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remeber_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password')
    return render_template('auth/login.html',form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm You Account',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account, Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or  current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

@auth.route('/comfirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm',user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))

@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.oldpassword.data):
            current_user.password = form.newpassword.data
            db.session.add(current_user)
            flash('You password had be changed')
        else:
            flash('Wrong old password!')
    return render_template('auth/change_password.html',form=form)

@auth.route('/reset-password', methods=['GET','POST'])
def reset_password_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',user=user, token=token)
        flash('A reset password email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html',form=form)

@auth.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            flash("can't find the user")
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('You password has been update')
            return redirect(url_for('auth.login'))
        else:
            flash('invalid message')
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html',form=form)


@auth.route('/change-email', methods=['GET','POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.email != form.email.data or not current_user.verify_password(form.password.data):
            flash('Invalide email or password')
        else:
            token = current_user.generate_email_change_token(form.newemail.data)
            send_email(form.newemail.data, 'Confirm Your Email',
                       'auth/email/change_email',token=token,user=current_user)
            flash('An confirm email has been send to you new Email address')
            return redirect(url_for('main.index'))
    return render_template('auth/change_email.html',form=form)

@auth.route('/change-email/<token>',methods=['GET','POST'])
@login_required
def change_email(token):
    if current_user.confirm_email_change(token):
        flash('You email address has been upgrate')
    else:
        flash('Invalid request')
    return redirect(url_for('main.index'))



