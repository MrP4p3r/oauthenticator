"""The fake OIDC provider: discovery, authorization, token, userinfo,
introspection and revocation, minting real RS256-signed tokens.

Built fresh per test (see the `oidc_provider` / `provider_factory` fixtures
in conftest.py) so issued codes, refresh tokens and injected failures never
leak between tests. Reached exclusively through httpx.ASGITransport in
tests, never bound to a socket.

Failure simulation
    `fail_authorization` redirects the browser back with an error instead of
    a code. `fail_token_request` makes the token endpoint return an
    arbitrary status and body, JSON or not, in place of a normal response.
    Both are `None` by default, meaning "behave".
"""

import secrets
import time
import urllib.parse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

from oauthenticator.oauth2 import pkce

ACCESS_TOKEN_LIFETIME = 3600
REFRESH_TOKEN_LIFETIME = 86400

ISSUER = 'https://issuer.test'
CLIENT_ID = 'test-client'
CLIENT_SECRET = 'test-secret'


def build_http_client(provider):
    """An httpx.AsyncClient wired to one provider instance through ASGITransport.

    A plain function rather than a fixture, so a test that builds its own
    provider through `provider_factory` (to simulate a capability toggle or
    a failure) can still get a client for it without a second fixture.
    """
    transport = httpx.ASGITransport(app=provider.app)

    return httpx.AsyncClient(transport=transport, base_url=provider.issuer)


class FakeOidcProvider:
    """An in-process OIDC provider, minting real RS256 tokens from an injected signer."""

    def __init__(self, *, issuer, signer, client_id, client_secret=None,
                token_endpoint_auth_methods=('client_secret_basic', 'client_secret_post'),
                include_userinfo=True, include_introspection=True,
                include_revocation=True, include_end_session=True):
        self.issuer = issuer
        self.signer = signer
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint_auth_methods = list(token_endpoint_auth_methods)
        self.include_userinfo = include_userinfo
        self.include_introspection = include_introspection
        self.include_revocation = include_revocation
        self.include_end_session = include_end_session

        self.identity_claims = {
            'sub': 'user-1', 'name': 'Ada Lovelace', 'email': 'ada@example.com',
            'email_verified': True,
        }
        self.authorization_requests = {}
        self.issued_refresh_tokens = {}
        self.fail_authorization = None
        self.fail_token_request = None
        self.captured_token_request = None
        self.captured_authorization_header = None

        self.app = self._build_app()

    def _build_app(self):
        app = FastAPI()
        app.get('/.well-known/openid-configuration')(self._discovery)
        app.get('/authorize')(self._authorize)
        app.post('/token')(self._token)

        if self.include_userinfo:
            app.get('/userinfo')(self._userinfo)
        if self.include_introspection:
            app.post('/introspect')(self._introspect)
        if self.include_revocation:
            app.post('/revoke')(self._revoke)

        return app

    async def _discovery(self):
        config = {
            'issuer': self.issuer,
            'authorization_endpoint': f'{self.issuer}/authorize',
            'token_endpoint': f'{self.issuer}/token',
            'token_endpoint_auth_methods_supported': self.token_endpoint_auth_methods,
        }

        if self.include_userinfo:
            config['userinfo_endpoint'] = f'{self.issuer}/userinfo'
        if self.include_introspection:
            config['introspection_endpoint'] = f'{self.issuer}/introspect'
        if self.include_revocation:
            config['revocation_endpoint'] = f'{self.issuer}/revoke'
        if self.include_end_session:
            config['end_session_endpoint'] = f'{self.issuer}/end_session'

        return config

    async def _authorize(self, request: Request):
        params = dict(request.query_params)
        redirect_uri = params['redirect_uri']

        if self.fail_authorization is not None:
            response_params = dict(self.fail_authorization)
            if params.get('state'):
                response_params.setdefault('state', params['state'])

            return self._redirect(redirect_uri, response_params)

        code = secrets.token_urlsafe(16)
        self.authorization_requests[code] = params

        return self._redirect(redirect_uri, {'code': code, 'state': params.get('state', '')})

    async def _token(self, request: Request):
        form = dict(await request.form())
        self.captured_token_request = form
        self.captured_authorization_header = request.headers.get('authorization')

        if self.fail_token_request is not None:
            status_code, body = self.fail_token_request

            return PlainTextResponse(body, status_code=status_code)

        if not self._authenticated(form, request):
            return JSONResponse({'error': 'invalid_client'}, status_code=401)

        if form.get('grant_type') == 'authorization_code':
            return self._issue_from_code(form)
        if form.get('grant_type') == 'refresh_token':
            return self._issue_from_refresh(form)

        return JSONResponse({'error': 'unsupported_grant_type'}, status_code=400)

    def _issue_from_code(self, form):
        authorization_request = self.authorization_requests.pop(form.get('code'), None)
        if authorization_request is None:
            return JSONResponse(
                {'error': 'invalid_grant', 'error_description': 'unknown or reused code'},
                status_code=400)

        if form.get('redirect_uri') != authorization_request['redirect_uri']:
            return JSONResponse(
                {'error': 'invalid_grant', 'error_description': 'redirect_uri mismatch'},
                status_code=400)

        challenge = pkce.code_challenge(form.get('code_verifier') or '')
        if challenge != authorization_request.get('code_challenge'):
            return JSONResponse(
                {'error': 'invalid_grant', 'error_description': 'PKCE verification failed'},
                status_code=400)

        return self._issue_tokens(
            authorization_request.get('scope', ''), nonce=authorization_request.get('nonce'))

    def _issue_from_refresh(self, form):
        scope = self.issued_refresh_tokens.pop(form.get('refresh_token'), None)
        if scope is None:
            return JSONResponse(
                {'error': 'invalid_grant', 'error_description': 'unknown refresh token'},
                status_code=400)

        return self._issue_tokens(scope, nonce=None)

    def _issue_tokens(self, scope, nonce):
        now = int(time.time())
        access_claims = {
            **self.identity_claims, 'iss': self.issuer, 'aud': self.client_id,
            'iat': now, 'exp': now + ACCESS_TOKEN_LIFETIME, 'scope': scope,
        }
        response = {
            'access_token': self.signer.sign(access_claims),
            'token_type': 'Bearer',
            'expires_in': ACCESS_TOKEN_LIFETIME,
        }

        if 'openid' in scope.split():
            id_claims = dict(access_claims)
            if nonce is not None:
                id_claims['nonce'] = nonce
            response['id_token'] = self.signer.sign(id_claims)

        refresh_token = secrets.token_urlsafe(24)
        self.issued_refresh_tokens[refresh_token] = scope
        response['refresh_token'] = refresh_token
        response['refresh_expires_in'] = REFRESH_TOKEN_LIFETIME

        return response

    async def _userinfo(self, request: Request):
        authorization = request.headers.get('authorization', '')
        if not authorization.startswith('Bearer '):
            return JSONResponse({'error': 'invalid_token'}, status_code=401)

        return dict(self.identity_claims)

    async def _introspect(self, request: Request):
        form = dict(await request.form())
        self.captured_token_request = form
        self.captured_authorization_header = request.headers.get('authorization')

        return {'active': True, 'sub': self.identity_claims['sub'],
               'token_type_hint': form.get('token_type_hint')}

    async def _revoke(self, request: Request):
        form = dict(await request.form())
        self.captured_token_request = form
        self.captured_authorization_header = request.headers.get('authorization')

        return PlainTextResponse('')

    def _authenticated(self, form, request):
        """Whether *some* credential arrived in the place this provider advertises.

        Deliberately does not re-derive the RFC 6749 SS2.3.1 encoding itself
        -- that would just duplicate the client's algorithm inside the
        double and could hide the same bug on both sides. The header's exact
        bytes are checked independently, against a value computed in the
        test, not here.
        """
        if self.client_secret is None:
            return True

        authorization = request.headers.get('authorization')
        if authorization is not None:
            return authorization.startswith('Basic ')

        return form.get('client_secret') == self.client_secret

    @staticmethod
    def _redirect(redirect_uri, params):
        separator = '&' if '?' in redirect_uri else '?'

        return RedirectResponse(redirect_uri + separator + urllib.parse.urlencode(params),
                                status_code=302)
