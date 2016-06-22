from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask.ext.login import UserMixin, AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app

class Permission:
    '''Role Permission'''
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x10

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permission = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        '''add new roles to sql'''
        roles = {
            'User':(Permission.FOLLOW |
                    Permission.COMMENT |
                    Permission.WRITE_ARTICLES, True),
            'Moderator':(Permission.FOLLOW |
                         Permission.COMMENT |
                         Permission.WRITE_ARTICLES |
                         Permission.MODERATE_COMMENTS, False),
            'Administrator':(0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permission = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            self.role = Role.query.filter_by(default=True).first()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset':self.id})

    def reset_password(self, token, password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            print 'invalid password reset token'
            return False
        if data.get('reset') != self.id:
            print 'Wrong password reset token'
            return False
        self.password = password
        db.session.add(self)
        print 'Reset the password succeed'
        return True

    def generate_email_change_token(self, newemail, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change':self.id, 'email':newemail})

    def confirm_email_change(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            print 'Invalid email change token'
            return False
        if data.get('change') != self.id:
            print 'Wrong email change token'
            return False
        self.email = data.get('email')
        db.session.add(self)
        print 'Email has been changed'
        return True

    def can(self,permission):
        '''user permission check'''
        return self.role is not None and (self.role.permission & permission) == permission

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def ping(self):
        '''update last_seen'''
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def __repr__(self):
        return '<User %r>' % self.username

class AnonymousUser(AnonymousUserMixin):
    def can(self, permission):
        return False

    def is_administrator(self):
        return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

login_manager.anonymous_user = AnonymousUser
