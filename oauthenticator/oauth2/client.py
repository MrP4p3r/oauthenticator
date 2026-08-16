"""Talks to the provider: discovery, authorization URL and token operations.

Client authentication
    With a secret the token request uses client_secret_basic, falling back
    to client_secret_post when discovery advertises only that method. RFC
    6749 SS2.3.1 requires the client id and secret to be form-urlencoded
    before base64; httpx.BasicAuth does not do that (it just utf-8 encodes
    and joins), so the header stays hand-rolled here. The same choice
    applies to the refresh, introspection and revocation calls.

Transport is an injected httpx.AsyncClient: this module builds none of its
own, so callers control its lifetime and tests can point it at an
in-process ASGI app through httpx.ASGITransport with no sockets involved.
"""

import base64
import urllib.parse

import httpx

from oauthenticator.oauth2 import discovery, flow
from oauthenticator.oauth2.errors import ProviderRequestError


class OidcClient:
    """Talks to the provider: discovery, authorization URL, token operations."""

    def __init__(self, http_client, issuer, client_id, client_secret):
        self.http_client = http_client
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.config = {}

    async def discover(self):
        url = discovery.discovery_url(self.issuer)
        self.config = await self._request('GET', url)
        discovery.validate(self.config, url)

        return self.config

    def supports(self, endpoint):
        return discovery.supports(self.config, endpoint)

    def authorization_url(self, redirect_uri, scope, state, nonce, code_challenge):
        return flow.authorization_url(
            self.config, self.client_id, redirect_uri, scope, state, nonce, code_challenge)

    async def exchange_code(self, code, redirect_uri, code_verifier):
        return await self._token_request({
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.client_id,
            'code_verifier': code_verifier,
        })

    async def refresh(self, refresh_token):
        return await self._token_request({
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id,
        })

    async def userinfo(self, access_token):
        url = discovery.endpoint_url(self.config, 'userinfo_endpoint')
        headers = {'Authorization': 'Bearer ' + access_token, 'Accept': 'application/json'}

        return await self._request('GET', url, headers=headers)

    def end_session_url(self, id_token, post_logout_redirect):
        url = discovery.endpoint_url(self.config, 'end_session_endpoint')

        return flow.end_session_url(url, self.client_id, id_token, post_logout_redirect)

    async def introspect(self, token, hint):
        return await self._token_action('introspection_endpoint', token, hint)

    async def revoke(self, token, hint):
        return await self._token_action('revocation_endpoint', token, hint)

    async def _token_request(self, form):
        headers = {'Accept': 'application/json'}
        self._authenticate(form, headers)

        return await self._request('POST', self.config['token_endpoint'],
                                   headers=headers, data=form)

    async def _token_action(self, endpoint, token, hint):
        url = discovery.endpoint_url(self.config, endpoint)
        form = {'token': token, 'token_type_hint': hint, 'client_id': self.client_id}
        headers = {'Accept': 'application/json'}
        self._authenticate(form, headers)

        return await self._request('POST', url, headers=headers, data=form)

    def _authenticate(self, form, headers):
        if self.client_secret is None:
            return

        if self._prefers_basic_auth():
            headers['Authorization'] = self._basic_auth_header()
        else:
            form['client_secret'] = self.client_secret

    def _prefers_basic_auth(self):
        methods = self.config.get('token_endpoint_auth_methods_supported') or []

        return 'client_secret_post' not in methods or 'client_secret_basic' in methods

    def _basic_auth_header(self):
        user = urllib.parse.quote(self.client_id, safe='')
        password = urllib.parse.quote(self.client_secret, safe='')
        credentials = base64.b64encode(f'{user}:{password}'.encode()).decode()

        return 'Basic ' + credentials

    async def _request(self, method, url, *, headers=None, data=None):
        try:
            response = await self.http_client.request(method, url, headers=headers, data=data)
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            detail = error.response.text.strip()
            raise ProviderRequestError(
                f'{url} -> HTTP {error.response.status_code} {error.response.reason_phrase}\n'
                f'{detail}') from error
        except httpx.HTTPError as error:
            raise ProviderRequestError(f'{url} -> {error}') from error

        return self._parse(response)

    @staticmethod
    def _parse(response):
        body = response.text
        if not body.strip():
            return {}

        try:
            return response.json()
        except ValueError:
            return {'response': body}
