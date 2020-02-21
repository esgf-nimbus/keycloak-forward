import datetime
import json
import os

import requests
import uuid
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt
from authlib.oidc.core import CodeIDToken
from flask import redirect
from flask import request
from flask import session
from flask import Response
from flask_sqlalchemy import SQLAlchemy

from keycloak_forward.utils import keycloak_discover
from keycloak_forward.utils import keycloak_jwk

class KeyCloakForward(object):
    def __init__(self, app=None):
        self.app = app

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.config.update(
            SQLALCHEMY_DATABASE_URI = 'sqlite://',
            SQLALCHEMY_TRACK_MODIFICATIONS = False,
        )

        if 'KEYCLOAK_FORWARD_CONFIG' in os.environ:
            app.config.from_envvar('KEYCLOAK_FORWARD_CONFIG')

        app.logger.info('Bootstrapping keycloak openid configuration')

        discovered = keycloak_discover(app.config['KEYCLOAK_DISCOVERY_URL'])

        app.logger.info('Retrieving JWK')

        keys = keycloak_jwk(discovered['jwks_uri'])

        self.key = keys[0]

        self.authorization_url = discovered['authorization_endpoint']

        self.token_url = discovered['token_endpoint']

        self.client = OAuth2Session(
            app.config['KEYCLOAK_CLIENT_ID'],
            app.config['KEYCLOAK_CLIENT_SECRET'],
            scope=app.config['KEYCLOAK_SCOPE'],
            redirect_uri=app.config['KEYCLOAK_REDIRECT_URI']
        )

        db = SQLAlchemy(app)

        class AuthRequest(db.Model):
            id = db.Column(db.String(8), unique=True, primary_key=True)
            origin = db.Column(db.String(256))
            allowed = db.Column(db.Boolean)
            roles = db.Column(db.String(256))
            groups = db.Column(db.String(256))
            upstream_headers = db.Column(db.String(2048))

        self.db = db

        self.auth_request = AuthRequest

        self.db.create_all()

    def is_token_bearer(self, headers):
        return 'Authorization' in headers

    def roles_and_groups_from_args(self, args):
        roles = set([x.strip() for x in args.get('roles', '').split(',') if x != ''])

        groups = set([x.strip() for x in args.get('groups', '').split(',') if x != ''])

        return roles, groups

    def roles_and_groups_from_claims(self, claims):
        roles = set(claims.get('roles', []))

        groups = set(claims.get('groups', []))

        return roles, groups

    def roles_and_groups_from_entry(self, entry):
        roles = set([x.strip() for x in entry.roles.split(',') if x != ''])

        groups = set([x.strip() for x in entry.groups.split(',') if x != ''])

        return roles, groups

    def is_authorized(self, roles, groups, claims_roles, claims_groups):
        self.app.logger.debug(f'Roles {roles} groups {groups} claims_roles {claims_roles} claims_groups {claims_groups}')

        if len(roles) > 0:
            valid_roles = roles == claims_roles
        else:
            valid_roles = True

        if len(groups) > 0:
            valid_groups = len(groups & claims_groups) > 0
        else:
            valid_groups = True

        self.app.logger.info(f'Valid roles {valid_roles!r} groups {valid_groups!r}')

        return valid_roles and valid_groups

    def bearer_authorized(self, headers, args):
        self.app.logger.info(f'Checking if bearer is authorized')

        _, token = headers['Authorization'].split(' ')

        claims = jwt.decode(token, self.key)

        claims.validate()

        roles, groups = self.roles_and_groups_from_args(args)

        claims_roles, claims_groups = self.roles_and_groups_from_claims(claims)

        return ('Success', 200) if self.is_authorized(roles, groups, claims_roles, claims_groups) else ('Unauthorized', 403)

    def get_client_id(self, session):
        if 'id' not in session:
            session['id'] = str(uuid.uuid4())[:8]

        return session['id']

    def build_origin(self, headers):
        return f'{headers["X-Forwarded-Proto"]!s}://{headers["X-Forwarded-Host"]!s}{headers["X-Forwarded-Uri"]!s}'

    def redirect_or_forward(self, session, headers, args):
        id = self.get_client_id(session)

        entry = self.auth_request.query.filter_by(id=id).first()

        if entry is None:
            self.app.logger.info(f'Processing new auth request for client id {id!s}')

            uri, state = self.client.create_authorization_url(self.authorization_url, scope=self.app.config['KEYCLOAK_SCOPE'])

            origin = self.build_origin(headers)

            roles, groups = self.roles_and_groups_from_args(args)

            entry = self.auth_request(id=id, origin=origin, allowed=False, roles=','.join(roles), groups=','.join(groups))

            self.db.session.add(entry)
            self.db.session.commit()

            self.app.logger.info(f'Redirecting client id {id!s} to authorization server')

            result = redirect(uri)
        else:
            self.app.logger.info(f'Processing acknowledged request for client id {id!s}')

            self.db.session.delete(entry)
            self.db.session.commit()

            if entry.allowed:
                self.app.logger.info(f'Allowing request for client id {id!s}')

                result = Response('Success', 200, json.loads(entry.upstream_headers))
            else:
                self.app.logger.info(f'Denying request for client id {id!s}')

                result = ('Unauthorized', 403)

        return result

    def stringify_value(self, value):
        if isinstance(value, (list, tuple)):
            value = ','.join(value)
        elif isinstance(value, dict):
            value = json.dumps(value)
        elif isinstance(value, datetime.datetime):
            value = value.isoformat()
        elif isinstance(value, datetime.timedelta):
            value = value.total_seconds()

        return value

    def gather_upstream_headers(self, claims):
        upstream = {}
        headers = self.app.config.get('KEYCLOAK_UPSTREAM_HEADERS', '').split(' ')

        for x in headers:
            value = claims.get(x)

            if value is not None:
                key = f'X-Auth-{x.capitalize()!s}'

                upstream[key] = self.stringify_value(value)

        return upstream

    def fetch_token_and_check_authorization(self, session, response_url):
        id = self.get_client_id(session)

        self.app.logger.info(f'Processing callback for client id {id!s}')

        entry = self.auth_request.query.filter_by(id=id).first()

        if entry is None:
            return ('Error', 500)

        token = self.client.fetch_token(self.token_url, authorization_response=response_url, scope=self.app.config['KEYCLOAK_SCOPE'])

        claims = jwt.decode(token['access_token'], self.key)

        claims.validate()

        self.app.logger.debug(f'Claims {claims}')

        claims_roles, claims_groups = self.roles_and_groups_from_claims(claims)

        roles, groups = self.roles_and_groups_from_entry(entry)

        if self.is_authorized(roles, groups, claims_roles, claims_groups):
            entry.allowed = True

            entry.upstream_headers = json.dumps(self.gather_upstream_headers(claims))

            self.app.logger.debug(f'Client id {id!s} upstream headers {entry.upstream_headers!r}')

            self.db.session.add(entry)
            self.db.session.commit()

            self.app.logger.info(f'Client id {id!s} is authorized, setting upstream headers')

        self.app.logger.info(f'Redirecting client id {id!r} to origin {entry.origin!s}')

        return redirect(entry.origin)
