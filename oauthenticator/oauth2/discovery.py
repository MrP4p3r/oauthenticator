"""Discovery document handling.

Reads <issuer>/.well-known/openid-configuration and takes the endpoints from
there, so only an issuer URL is needed instead of a per-provider list of
URLs. Fails early when authorization_endpoint or token_endpoint is absent.
The userinfo, introspection and revocation endpoints are optional: the
caller offers each action only when the provider advertises it.
"""

from oauthenticator.oauth2.errors import DiscoveryError

DISCOVERY_PATH = '/.well-known/openid-configuration'
REQUIRED_ENDPOINTS = ('authorization_endpoint', 'token_endpoint')


def discovery_url(issuer):
    return issuer.rstrip('/') + DISCOVERY_PATH


def validate(config, url):
    for key in REQUIRED_ENDPOINTS:
        if key not in config:
            raise DiscoveryError(f'{key} is missing in {url}')


def supports(config, endpoint):
    return isinstance(config.get(endpoint), str)


def endpoint_url(config, name):
    url = config.get(name)
    if not isinstance(url, str):
        raise DiscoveryError(f'{name} is missing in the discovery document')

    return url
