import pytest
from authlib.jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from flask import Flask
from werkzeug.wrappers import Response

from keycloak_forward import keycloak_forward as kc

@pytest.fixture
def key_pair():
    key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)

    public_key = key.public_key()

    return key, public_key

@pytest.fixture
def token(key_pair):
    header = {'alg': 'RS256'}
    payload = {'iss': 'Testing', 'sub': '123', 'aud': 'compute'}
    return jwt.encode(header, payload, key_pair[0]).decode()

@pytest.fixture
def forward(mocker):
    app = Flask(__name__)

    app.config['TESTING'] = True

    app.config.update(
        CLIENT_ID = '<CLIENT_ID>',
        CLIENT_SECRET = '<CLIENT_SECRET>',
        SCOPE = 'openid roles groups',
        REDIRECT_URI = 'https://localhost/callback',
        KEYCLOAK_DISCOVERY_URL = 'http://httpbin.org/status/200',
    )

    mocker.patch.object(kc, 'utils')

    f = kc.KeyCloakForward(app)

    f.authorization_url = 'http://localhost/authorization'
    f.token_url = 'http://localhost/token'

    yield f

def test_fetch_token_and_check_authorization_failed(forward, mocker, token, key_pair):
    session = {}
    response_url = ''

    mocker.patch.object(forward, 'get_client_id', return_value=0)

    mocker.patch.object(forward.client, 'fetch_token', return_value={'access_token': token})

    forward.key = key_pair[1]

    entry = forward.auth_request(id=0, origin='http://localhost/wps', allowed=False, roles='admin', groups='')

    forward.db.session.add(entry)
    forward.db.session.commit()

    output = forward.fetch_token_and_check_authorization(session, response_url)

    entry = forward.auth_request.query.filter_by(id=0).first()

    assert not entry.allowed

    assert isinstance(output, Response)
    assert output.location == 'http://localhost/wps'

def test_fetch_token_and_check_authorization(forward, mocker, token, key_pair):
    session = {}
    response_url = ''

    mocker.patch.object(forward, 'get_client_id', return_value=0)

    mocker.patch.object(forward.client, 'fetch_token', return_value={'access_token': token})

    forward.key = key_pair[1]

    entry = forward.auth_request(id=0, origin='http://localhost/wps', allowed=False, roles='', groups='')

    forward.db.session.add(entry)
    forward.db.session.commit()

    output = forward.fetch_token_and_check_authorization(session, response_url)

    entry = forward.auth_request.query.filter_by(id=0).first()

    assert entry.allowed

    assert isinstance(output, Response)
    assert output.location == 'http://localhost/wps'

def test_redirect_or_forward_unauthorized(forward, mocker):
    header = {}
    args = {}

    mocker.patch.object(forward, 'get_client_id', return_value=0)

    entry = forward.auth_request(id=0, origin='http://localhost/wps', allowed=False, roles='', groups='')

    forward.db.session.add(entry)
    forward.db.session.commit()

    output = forward.redirect_or_forward({}, header, args)

    assert output == ('Unauthorized', 403)

def test_redirect_or_forward_success(forward, mocker):
    header = {}
    args = {}

    mocker.patch.object(forward, 'get_client_id', return_value=0)

    entry = forward.auth_request(id=0, origin='http://localhost/wps', allowed=True, roles='', groups='')

    forward.db.session.add(entry)
    forward.db.session.commit()

    output = forward.redirect_or_forward({}, header, args)

    assert output == ('Success', 200)

def test_redirect_or_forward(forward, mocker):
    header = {
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-Host': 'localhost',
        'X-Forwarded-Uri': '/wps',
    }
    args = {}

    mocker.patch.object(forward, 'get_client_id', return_value=0)

    output = forward.redirect_or_forward({}, header, args)

    assert isinstance(output, Response)
    assert forward.authorization_url in output.location

    entry = forward.auth_request.query.filter_by(id=0).first()

    assert entry
    assert entry.origin == 'http://localhost/wps'

def test_build_origin(forward):
    headers = {
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-Host': '127.0.0.1',
        'X-Forwarded-Uri': '/wps',
    }

    origin = forward.build_origin(headers)

    assert origin == 'http://127.0.0.1/wps'

def test_get_client_id(forward):
    id = forward.get_client_id({})

    assert id

def test_bearer_authorized_missing_role(forward, key_pair, token):
    header = {'Authorization': f'Bearer {token!s}'}
    args = {'roles': 'compute'}

    forward.key = key_pair[1]

    assert forward.bearer_authorized(header, args)

def test_bearer_authorized_invalid_token(forward, key_pair, token):
    header = {'Authorization': f'Bearer abcd'}
    args = {}

    forward.key = key_pair[1]

    with pytest.raises(Exception):
        assert forward.bearer_authorized(header, args)

def test_bearer_authorized(forward, key_pair, token):
    header = {'Authorization': f'Bearer {token!s}'}
    args = {}

    forward.key = key_pair[1]

    assert forward.bearer_authorized(header, args)

@pytest.mark.parametrize('roles,claims_roles,groups,claims_groups', [
    (set(['compute']), set(['compute']), set(['admin']), set(['name'])),
    (set(['compute']), set([]), set(['admin']), set(['admin', 'compute'])),
    (set([]), set([]), set(['admin']), set(['name'])),
    (set(['compute']), set(['admin', 'compute']), set([]), set([])),
])
def test_is_authorized_error(forward, roles, claims_roles, groups, claims_groups):
    with pytest.raises(Exception):
        assert forward.is_authorized(roles, groups, claims_roles, claims_groups)

@pytest.mark.parametrize('roles,claims_roles,groups,claims_groups', [
    (set(['compute']), set(['compute']), set(['admin']), set(['admin', 'compute'])),
    (set([]), set([]), set([]), set(['admin', 'compute'])),
    (set([]), set([]), set(['admin']), set(['admin', 'compute'])),
    (set([]), set(['admin', 'compute']), set([]), set([])),
    (set(['admin', 'compute']), set(['admin', 'compute']), set([]), set([])),
])
def test_is_authorized(forward, roles, claims_roles, groups, claims_groups):
    assert forward.is_authorized(roles, groups, claims_roles, claims_groups)

def test_roles_and_groups_from_entry(forward):
    entry = forward.auth_request(id=0, origin='', allowed=False, roles='user,admin', groups='admin,compute')

    roles, groups = forward.roles_and_groups_from_entry(entry)

    assert roles == set(['user', 'admin'])
    assert groups == set(['admin', 'compute'])

def test_roles_and_groups_from_claims_missing_key():
    f = kc.KeyCloakForward()

    roles, groups = f.roles_and_groups_from_claims({'roles': ['user', 'admin']})

    assert roles == set(['user', 'admin'])
    assert groups == set()

def test_roles_and_groups_from_claims():
    f = kc.KeyCloakForward()

    roles, groups = f.roles_and_groups_from_claims({'roles': ['user', 'admin'], 'groups': ['admin', 'compute']})

    assert roles == set(['user', 'admin'])
    assert groups == set(['admin', 'compute'])

def test_roles_and_groups_from_args_malformed():
    f = kc.KeyCloakForward()

    roles, groups = f.roles_and_groups_from_args({'roles': 'admin, compute', 'groups': 'admin,compute'})

    assert roles == set(['admin', 'compute'])
    assert groups == set(['admin', 'compute'])

def test_roles_and_groups_from_args():
    f = kc.KeyCloakForward()

    roles, groups = f.roles_and_groups_from_args({'roles': 'admin,compute', 'groups': 'admin,compute'})

    assert roles == set(['admin', 'compute'])
    assert groups == set(['admin', 'compute'])

def test_is_token_bearer_no_auth():
    f = kc.KeyCloakForward()

    assert not f.is_token_bearer({})

def test_is_token_bearer():
    f = kc.KeyCloakForward()

    assert f.is_token_bearer({'Authorization': 'Bearer sdasda'})
