import argparse
import requests
import tabulate
from authlib.jose import jwk
from authlib.integrations.requests_client import OAuth2Session

def keycloak_discover(discovery_url):
    if discovery_url[-1] == '/':
        discovery_url = discovery_url[:-1]

    discovery_url = f'{discovery_url!s}/.well-known/openid-configuration'

    response = requests.get(discovery_url)

    response.raise_for_status()

    return response.json()


def keycloak_jwk(jwks_url):
    response = requests.get(jwks_url)

    response.raise_for_status()

    data = response.json()

    return [jwk.loads(x) for x in data['keys']]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('discovery_url')
    parser.add_argument('client_id')
    parser.add_argument('client_secret')

    args = parser.parse_args()

    discovered = keycloak_discover(args.discovery_url)

    jwks_url = discovered['jwks_uri']

    keys = keycloak_jwk(jwks_url)

    client = OAuth2Session(args.client_id, args.client_secret, grant_type='client_credentials', scope='roles groups')

    token = client.fetch_token(discovered['token_endpoint'])

    print(tabulate.tabulate(token.items(), tablefmt='plain'))
