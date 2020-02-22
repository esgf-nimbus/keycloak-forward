import logging

from flask import request
from flask import session
from flask import Flask

def fix_prefix(prefix):
    if prefix == '':
        return prefix

    if prefix[0] != '/':
        prefix = f'/{prefix!s}'

    if prefix[-1] == '/':
        prefix = prefix[:-1]

    return prefix

def create_app(test_config=None):
    app = Flask(__name__)

    g = logging.getLogger('gunicorn.error')

    app.logger.handlers = g.handlers
    app.logger.setLevel(g.level)

    from keycloak_forward import keycloak_forward

    keycloak = keycloak_forward.KeyCloakForward(app)

    prefix = fix_prefix(os.environ.get('KEYCLOAK_URL_PREFIX', ''))

    @app.route(f'{prefix!s}/health')
    def health():
        return ('Ping', 200)

    @app.route(f'{prefix!s}/keycloak')
    def keycloak_entry():
        if keycloak.is_token_bearer(request.headers):
            return keycloak.bearer_authorized(request.headers, request.args)

        return keycloak.redirect_or_forward(session, request.headers, request.args)

    @app.route(f'{prefix!s}/keycloak/callback')
    def keycloak_callback():
        return keycloak.fetch_token_and_check_authorization(session, request.url)

    return app
