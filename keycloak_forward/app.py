import os

from flask import request
from flask import session
from flask import Flask
from keycloak_forward import keycloak_forward

app = Flask(__name__)

if 'KEYCLOAK_PROXY_CFG' in os.environ:
    app.config.from_envvar('KEYCLOAK_PROXY_CFG')

keycloak = keycloak_forward.KeyCloakForward(app)

@app.route('/keycloak')
def keycloak_entry():
    if keycloak.is_token_bearer(request.headers):
        return keycloak.bearer_authorized(request.headers, request.args)

    return keycloak.redirect_or_forward(session, request.headers, request.args)

@app.route('/keycloak/callback')
def keycloak_callback():
    return keycloak.fetch_token_and_check_authorization(session, request.url)
