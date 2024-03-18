import jwt
from time import time
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from flask_login import UserMixin
from lds.app import db, login
from lds.definitions import PERMISSIONS


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    permissions = db.Column(db.Integer)
    reset_pass = db.Column(db.Boolean)

    def __repr__(self):
        return '<User {}> ID: {}, Email: {}, Permissions: {}, Reset Pass: {}' \
            .format(self.username, self.id, self.email, self.permissions, self.permissions)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_password_reset_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            user_id = jwt.decode(token, current_app.config['SECRET_KEY'],
                                 algorithms=['HS256'])['reset_password']
        except jwt.exceptions.PyJWTError:
            # failed to decode, catches all jwt.exceptions
            return
        return load_user(user_id)

    @staticmethod
    def new(username=None, email=None, password=False, reset_pass=False, permissions=0):
        if username is None:
            username = input('Username: ')
        if email is None:
            email = input('Email: ')
        if password is False:
            password = input('Password:')
        user = User(username=username, email=email, reset_pass=reset_pass, permissions=permissions)
        if password is not None:
            user.set_password(password)
        return user

    def add_permission(self, permission):
        self.permissions += permission

    def remove_permission(self, permission):
        self.permissions -= permission

    def get_permissions(self):
        none = True
        superuser = False
        if self.permissions is not PERMISSIONS.none:
            none = False
            if self.permissions & PERMISSIONS.superuser:
                superuser = True
        permissions = {
            'none': none,
            'superuser': superuser,
            'admin': bool(self.permissions & PERMISSIONS.admin | superuser),
            'unusedperm_1': bool(self.permissions & PERMISSIONS.unusedperm_1 | superuser),
            'unusedperm_2': bool(self.permissions & PERMISSIONS.unusedperm_2 | superuser),
            'unusedperm_3': bool(self.permissions & PERMISSIONS.unusedperm_3 | superuser),
            'unusedperm_4': bool(self.permissions & PERMISSIONS.unusedperm_4 | superuser),
            'unusedperm_5': bool(self.permissions & PERMISSIONS.unusedperm_5 | superuser),
            'unusedperm_6': bool(self.permissions & PERMISSIONS.unusedperm_6 | superuser),
            'unusedperm_7': bool(self.permissions & PERMISSIONS.unusedperm_7 | superuser)
        }
        return permissions

    def list_permissions(self):
        perms = self.get_permissions()
        message = '<Permissions for user {}> Superuser: {}, Admin: {}, Unused1: {}, Unused2: {},' \
                  ' Unused3: {}, Unused4: {}, Unused5: {}, Unused6: {}, Unused7: {}'
        message = message.format(self.username, perms['superuser'], perms['admin'], perms['unusedperm_1'],
                                 perms['unusedperm_2'], perms['unusedperm_3'], perms['unusedperm_4'], perms['unusedperm_5'],
                                 perms['unusedperm_6'], perms['unusedperm_7'])
        return message


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    module = db.Column(db.String(50), index=True)
    message = db.Column(db.String(200))


@login.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
