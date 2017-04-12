# coding: utf8
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import backref, scoped_session, create_session
from sqlalchemy import Column, DateTime, Index, Integer, String, Text, text, Boolean, ForeignKey
from datetime import datetime, timedelta
from uuid import uuid4
from hashlib import sha256
try: 
    from . import db
except ValueError:
    import sys
    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = sys.argv[1]
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy()
    db.init_app(app)


Base = declarative_base()
metadata = Base.metadata

class ScopesMixin(object):

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    @scopes.setter
    def scopes(self, value):
        self._scopes = " ".join(value)


class Tokens(Base, ScopesMixin):
    __tablename__ = 'tokens'
    access_token = Column(String(256), primary_key=True, autoincrement=False)
    access_token_expire_date = Column(DateTime, nullable=False)
    refresh_token = Column(String(256), nullable=True)
    refresh_token_expire_date = Column(DateTime, nullable=True)
    _scopes = Column(Text, nullable=False)
    user_id = Column(String(128), ForeignKey('users.id',ondelete='CASCADE'), nullable=True)
    client_id = Column(String(128), ForeignKey('clients.id', ondelete='CASCADE'), nullable=False)
    grant_code = Column(String(256), ForeignKey('grant_codes.code', ondelete='CASCADE'))

    @classmethod
    def fetch_by_access_token(cls, access_token):
        return db.session.query(Tokens).filter_by(access_token=access_token).filter(cls.access_token_expire_date > datetime.now()).first()

    @classmethod
    def fetch_by_refresh_token(cls, refresh_token):
        return db.session.query(Tokens).filter_by(refresh_token=refresh_token).filter(cls.refresh_token_expire_date > datetime.now()).first()

    def create_token(self, new_scopes=None):
        new_token = Tokens()
        new_token.access_token = sha256(uuid4().hex).hexdigest()
        new_token.refresh_token = sha256(uuid4().hex).hexdigest()
        new_token.access_token_expire_date = self.access_token_expire_date
        new_token.refresh_token_expire_date = self.refresh_token_expire_date
        if new_scopes is not None:
            # TODO: スコープの範囲チェック
            new_token.scopes = new_scopes
        else:
            new_token.scopes = self.scopes
        new_token.user_id = self.user_id
        new_token.client_id = self.client_id
        new_token.grant_code = self.grant_code
        return new_token



    @classmethod
    def new(cls, user_id, client_id, scopes, grant_code=None, is_refresh=False):
        token = cls()
        token.access_token=sha256(uuid4().hex).hexdigest()
        token.access_token_expire_date=datetime.now()+timedelta(hours=1)
        token._scopes=scopes
        token.user_id=user_id
        token.client_id=client_id
        if is_refresh is True:
            token.refresh_token=sha256(uuid4().hex).hexdigest()
            token.refresh_token_expire_date=datetime.now()+timedelta(days=3)
        if grant_code is not None:
            token.grant_code=grant_code

        return token

    def to_dict(self):
        r = {
            'access_token': self.access_token,
            'token_type': "bearer",
            'expires_in': (self.access_token_expire_date - datetime.now()).total_seconds(),
            'refresh_token':self.refresh_token,
            'scopes': self.scopes
                }

        return {k: v for k, v in r.items() if v is not None}

class GrantCodes(Base, ScopesMixin):
    __tablename__ = 'grant_codes'
    code = Column(String(256), primary_key=True, autoincrement=False)
    expire_date = Column(DateTime, nullable=False)
    is_lapsed = Column(Boolean, default=False, nullable=False)
    _scopes = Column(Text, nullable=False)

    user_id = Column(String(128), ForeignKey('users.id',ondelete='CASCADE'), nullable=False)
    client_id = Column(String(128), ForeignKey('clients.id', ondelete='CASCADE'), nullable=False)
    redirect_uri = Column(String(256), nullable=False)

    tokens = db.relationship(
        'Tokens',
        primaryjoin="Tokens.grant_code==GrantCodes.code",
        foreign_keys="Tokens.grant_code",
        lazy='dynamic',
        cascade='all, delete-orphan',
        backref="granted_code")

    @classmethod
    def fetch_by_code(cls, code):
        return db.session.query(GrantCodes).filter_by(code=code).filter(cls.expire_date > datetime.now()).filter_by(is_lapsed=False).first()

    def lasped(self):
        self.is_lapsed = True

    @classmethod
    def new(cls, user_id, client_id, redirect_uri, scope):
        grant_code = cls()

        grant_code.code=sha256(uuid4().hex).hexdigest()
        grant_code.expire_date=datetime.now()+timedelta(minutes=30)
        grant_code._scopes=scope
        grant_code.user_id=user_id
        grant_code.client_id=client_id
        grant_code.redirect_uri = redirect_uri

        return grant_code



class Users(Base, ScopesMixin):
    __tablename__ = 'users'
    id = Column(String(128), primary_key=True, autoincrement=False)
    password = Column(String(128), nullable=False)
    _scopes = Column(String(128), nullable=False)
    is_restricted = Column(Boolean, nullable=False, default=False)

    images = db.relationship(
        'Images',
        primaryjoin="Images.user_id==Users.id",
        foreign_keys="Images.user_id",
        lazy='dynamic',
        cascade='all, delete-orphan',
        backref="user")

    grant_codes = db.relationship(
        'GrantCodes',
        primaryjoin="GrantCodes.user_id==Users.id",
        foreign_keys="GrantCodes.user_id",
        lazy='dynamic',
        cascade='all, delete-orphan',
        backref="user")

    tokens = db.relationship(
        'Tokens',
        primaryjoin="Tokens.user_id==Users.id",
        foreign_keys="Tokens.user_id",
        lazy='dynamic',
        cascade='all, delete-orphan',
        backref="user")

    @classmethod
    def new_user(cls, user_id, user_password):
        # type: (str, str, List[str]) -> Users
        scopes = ['add_image', 'get_image', 'list_image', 'delete_image']
        return cls(id=user_id, password=user_password, _scopes=" ".join(scopes))

    @classmethod
    def new_restricted_user(cls, user_id, user_password):
        scopes = ['list_image']
        return cls(id=user_id, password=user_password, _scopes=" ".join(scopes))

    @classmethod
    def fetch(cls, user_id, user_password):
        # type: (str, str) -> Union[Users, None]
        return db.session.query(Users).filter_by(id=user_id, password=user_password).first()

    def create_image(self, data):
        # type: (str) -> Images
        return Images(user_id=self.id, data=data)

    def to_dict(self):
        return {
            'user_id':  self.id,
            'scopes': self.scopes
                }


class Images(Base):
    __tablename__ = 'images'
    id = Column(String(128), primary_key=True)
    data = Column(Text, nullable=False)
    user_id = Column(String(128), ForeignKey('users.id',ondelete='CASCADE'), nullable=False)

    @classmethod
    def new(cls, user_id, data):
        # type: (str, str) -> Images
        return cls(user_id=user_id, data=data)

    @classmethod
    def fetch(cls, id):
        return db.session.query(Images).filter_by(id=id).first()

    def to_dict(self):
        
        return{
            'id': self.id,
            'user_id': self.user.id,
            'data': self.data
                }



class Clients(Base):
    __tablename__ = 'clients'
    id = Column(String(128), primary_key=True, autoincrement=False)
    secret = Column(String(128), nullable=False)
    name = Column(String(128), nullable=False)
    type = Column(String(128), nullable=False)
    redirect_uri = Column(String(256), nullable=False)

    grant_codes = db.relationship(
        'GrantCodes',
        primaryjoin="GrantCodes.client_id==Clients.id",
        foreign_keys="GrantCodes.client_id",
        lazy='dynamic',
        cascade='all, delete-orphan',
        backref="client")

    tokens = db.relationship(
        'Tokens',
        primaryjoin="Tokens.client_id==Clients.id",
        foreign_keys="Tokens.client_id",
        lazy='dynamic',
        cascade='all, delete-orphan',
        backref="client")

    @classmethod
    def new(cls, name, type, redirect_uri):
        id = sha256(uuid4().hex).hexdigest()
        secret = sha256(uuid4().hex).hexdigest()
        return cls(id=id, secret=secret, name=name, type=type, redirect_uri=redirect_uri)

    def to_dict(self, show_secret=False):
        
        r = {
            'id': self.id,
            'name': self.name,
            'type': self.type
                }
        if show_secret:
            r.update({'secret': self.secret})
        return r

    @classmethod
    def fetch(cls, client_id):
        return db.session.query(Clients).filter_by(id=client_id).first()

    @classmethod
    def authorize(cls, client_id, client_secret):
        return db.session.query(Clients).filter_by(id=client_id).filter_by(secret=client_secret).first()


if __name__ == "__main__":
    Base.metadata.create_all(db.get_engine(app))
    user = Users.new_user("poe", "poe")
    session = create_session(bind=db.get_engine(app), autocommit=False)
    session.add(user)
    session.commit()

    try:
        from eralchemy import render_er
        render_er(Base, '../er.png')
    except ImportError:
        pass

