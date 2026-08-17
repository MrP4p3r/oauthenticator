"""oauth2/client.py -- request building, client-authentication choice, error mapping.

Client authentication is exercised against the fake provider so the
captured Authorization header and form body are what actually went out over
(an in-process) HTTP, not just what a hand-rolled unit test expects.
"""

import base64
import contextlib
import json

import httpx
import pytest

from oauthenticator.oauth2 import pkce
from oauthenticator.oauth2.client import OidcClient
from oauthenticator.oauth2.errors import DiscoveryError, ProviderRequestError
from tests.plugins.oidc_provider.app import CLIENT_ID, CLIENT_SECRET, build_http_client

REDIRECT_URI = 'https://app.test/callback'


@contextlib.asynccontextmanager
async def connected_client(provider, *, client_id=CLIENT_ID, client_secret=CLIENT_SECRET):
    async with build_http_client(provider) as http_client:
        client = OidcClient(http_client, provider.issuer, client_id, client_secret)
        await client.discover()

        yield client


def inject_authorization_code(provider, code, *, code_verifier, scope='openid'):
    """Plants an authorization code on the fake provider, bypassing the front channel.

    The full authorization_url -> redirect -> callback round trip is covered
    end to end at the web layer (tests/test_web.py); here only the token
    exchange itself is under test, so the code is planted directly.
    """
    provider.authorization_requests[code] = {
        'redirect_uri': REDIRECT_URI, 'scope': scope, 'nonce': None,
        'code_challenge': pkce.code_challenge(code_verifier),
    }


class _RaisingHttpClient:
    """A double standing in for httpx.AsyncClient, raising a transport-level error."""

    def __init__(self, error):
        self.error = error

    async def request(self, *args, **kwargs):
        raise self.error


async def test_discover_returns_the_validated_config(oidc_provider):
    async with connected_client(oidc_provider) as client:
        assert client.config['token_endpoint'] == f'{oidc_provider.issuer}/token'


async def test_discover_raises_when_a_required_endpoint_is_missing():
    async def handler(request):
        return httpx.Response(200, json={'authorization_endpoint': 'https://issuer.test/authorize'})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url='https://issuer.test') as http_client:
        client = OidcClient(http_client, 'https://issuer.test', CLIENT_ID, CLIENT_SECRET)

        with pytest.raises(DiscoveryError, match='token_endpoint'):
            await client.discover()


async def test_supports_reflects_the_discovery_document(provider_factory):
    provider = provider_factory(include_end_session=False)

    async with connected_client(provider) as client:
        assert client.supports('userinfo_endpoint') is True
        assert client.supports('end_session_endpoint') is False


async def test_exchange_code_returns_real_signed_tokens(oidc_provider):
    inject_authorization_code(oidc_provider, 'a-code', code_verifier='a-verifier')

    async with connected_client(oidc_provider) as client:
        tokens = await client.exchange_code('a-code', REDIRECT_URI, 'a-verifier')

        assert 'access_token' in tokens
        assert 'id_token' in tokens
        header = json.loads(base64.urlsafe_b64decode(tokens['access_token'].split('.')[0] + '=='))
        assert header['alg'] == 'RS256'


class TestClientAuthentication:
    """Which credential channel exchange_code (and friends) use."""

    async def test_prefers_client_secret_basic_by_default(self, oidc_provider):
        inject_authorization_code(oidc_provider, 'a-code', code_verifier='a-verifier')

        async with connected_client(oidc_provider) as client:
            await client.exchange_code('a-code', REDIRECT_URI, 'a-verifier')

        assert oidc_provider.captured_authorization_header.startswith('Basic ')
        assert 'client_secret' not in oidc_provider.captured_token_request

    async def test_falls_back_to_client_secret_post_when_only_that_is_advertised(
            self, provider_factory):
        provider = provider_factory(token_endpoint_auth_methods=['client_secret_post'])
        inject_authorization_code(provider, 'a-code', code_verifier='a-verifier')

        async with connected_client(provider) as client:
            await client.exchange_code('a-code', REDIRECT_URI, 'a-verifier')

        assert provider.captured_authorization_header is None
        assert provider.captured_token_request['client_secret'] == CLIENT_SECRET

    async def test_public_client_sends_no_credentials_at_all(self, provider_factory):
        provider = provider_factory(client_secret=None)
        inject_authorization_code(provider, 'a-code', code_verifier='a-verifier')

        async with connected_client(provider, client_secret=None) as client:
            await client.exchange_code('a-code', REDIRECT_URI, 'a-verifier')

        assert provider.captured_authorization_header is None
        assert 'client_secret' not in provider.captured_token_request

    async def test_percent_encodes_reserved_characters_in_the_basic_auth_header(
            self, provider_factory):
        # RFC 6749 SS2.3.1: client_id and client_secret are form-urlencoded
        # before being base64-joined -- httpx.BasicAuth does not do this, so
        # this behaviour is hand-rolled and worth locking to an exact value,
        # computed independently of oauth2/client.py (see the comment below).
        weird_client_id = 'client:id@x/y z'
        weird_client_secret = 'sec:ret@val/ue z'
        expected_header = 'Basic Y2xpZW50JTNBaWQlNDB4JTJGeSUyMHo6c2VjJTNBcmV0JTQwdmFsJTJGdWUlMjB6'
        provider = provider_factory(client_id=weird_client_id, client_secret=weird_client_secret)
        inject_authorization_code(provider, 'a-code', code_verifier='a-verifier')

        async with connected_client(
                provider, client_id=weird_client_id, client_secret=weird_client_secret) as client:
            await client.exchange_code('a-code', REDIRECT_URI, 'a-verifier')

        assert provider.captured_authorization_header == expected_header


def test_basic_auth_header_percent_encodes_reserved_characters_directly():
    # expected_header derived the same way as above: RFC 3986 unreserved-set
    # percent-encoding (urllib.parse.quote(..., safe='')) of each half,
    # joined with ':' and base64-encoded -- independent of this module.
    client = OidcClient(http_client=None, issuer='https://issuer.test',
                        client_id='client:id@x/y z', client_secret='sec:ret@val/ue z')

    assert (client._basic_auth_header() ==
           'Basic Y2xpZW50JTNBaWQlNDB4JTJGeSUyMHo6c2VjJTNBcmV0JTQwdmFsJTJGdWUlMjB6')


async def test_introspect_and_revoke_send_the_given_hint(oidc_provider):
    async with connected_client(oidc_provider) as client:
        await client.introspect('a-token', hint='refresh_token')
        assert oidc_provider.captured_token_request['token_type_hint'] == 'refresh_token'

        await client.revoke('a-token', hint='access_token')
        assert oidc_provider.captured_token_request['token_type_hint'] == 'access_token'


async def test_revoke_with_an_empty_response_body_returns_an_empty_dict(oidc_provider):
    async with connected_client(oidc_provider) as client:
        result = await client.revoke('a-token', hint='access_token')

        assert result == {}


async def test_userinfo_raises_when_the_endpoint_is_not_advertised(provider_factory):
    provider = provider_factory(include_userinfo=False)

    async with connected_client(provider) as client:
        with pytest.raises(DiscoveryError, match='userinfo_endpoint'):
            await client.userinfo('some-access-token')


class TestErrorMapping:
    """No httpx exception escapes the oauth2/ layer."""

    async def test_http_status_error_becomes_a_provider_request_error(self, oidc_provider):
        oidc_provider.fail_token_request = (400, json.dumps(
            {'error': 'invalid_grant', 'error_description': 'bad code'}))

        async with connected_client(oidc_provider) as client:
            with pytest.raises(ProviderRequestError, match='invalid_grant'):
                await client.exchange_code('any-code', REDIRECT_URI, 'verifier')

    async def test_a_non_json_error_body_is_still_wrapped_without_raising(self, oidc_provider):
        oidc_provider.fail_token_request = (502, 'Bad Gateway, not JSON at all')

        async with connected_client(oidc_provider) as client:
            with pytest.raises(ProviderRequestError, match='Bad Gateway'):
                await client.exchange_code('any-code', REDIRECT_URI, 'verifier')

    async def test_a_non_json_success_body_falls_back_to_a_response_wrapper(self, oidc_provider):
        oidc_provider.fail_token_request = (200, 'not-json-at-all')

        async with connected_client(oidc_provider) as client:
            result = await client.exchange_code('any-code', REDIRECT_URI, 'verifier')

        assert result == {'response': 'not-json-at-all'}

    async def test_a_transport_level_error_is_wrapped_too(self):
        http_client = _RaisingHttpClient(httpx.ReadTimeout('timed out'))
        client = OidcClient(http_client, 'https://issuer.test', CLIENT_ID, CLIENT_SECRET)
        client.config = {'token_endpoint': 'https://issuer.test/token'}

        with pytest.raises(ProviderRequestError, match='timed out'):
            await client.exchange_code('any-code', REDIRECT_URI, 'verifier')
