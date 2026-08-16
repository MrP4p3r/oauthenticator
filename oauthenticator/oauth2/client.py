"""Talks to the provider: discovery, authorization URL and token operations.

Client authentication
    With a secret the token request uses client_secret_basic, falling back
    to client_secret_post when discovery advertises only that method. Basic
    credentials are form-urlencoded first, as RFC 6749 requires. The same
    choice applies to the refresh, introspection and revocation calls.

Transport stays on urllib.request for now; nothing here is async, and there
is no injected HTTP client yet.
"""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from oauthenticator.oauth2 import discovery, flow
from oauthenticator.oauth2.errors import ProviderRequestError


class OidcClient:
    """Talks to the provider: discovery, authorization URL, token operations."""

    def __init__(self, issuer, client_id, client_secret):
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.config = {}

    def discover(self):
        url = discovery.discovery_url(self.issuer)
        self.config = self._request(url)
        discovery.validate(self.config, url)

        return self.config

    def supports(self, endpoint):
        return discovery.supports(self.config, endpoint)

    def authorization_url(self, redirect_uri, scope, state, nonce, code_challenge):
        return flow.authorization_url(
            self.config, self.client_id, redirect_uri, scope, state, nonce, code_challenge)

    def exchange_code(self, code, redirect_uri, code_verifier):
        return self._token_request({
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.client_id,
            'code_verifier': code_verifier,
        })

    def refresh(self, refresh_token):
        return self._token_request({
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id,
        })

    def userinfo(self, access_token):
        url = discovery.endpoint_url(self.config, 'userinfo_endpoint')
        headers = {'Authorization': 'Bearer ' + access_token, 'Accept': 'application/json'}

        return self._request(url, headers=headers)

    def end_session_url(self, id_token, post_logout_redirect):
        url = discovery.endpoint_url(self.config, 'end_session_endpoint')

        return flow.end_session_url(url, self.client_id, id_token, post_logout_redirect)

    def introspect(self, token, hint):
        return self._token_action('introspection_endpoint', token, hint)

    def revoke(self, token, hint):
        return self._token_action('revocation_endpoint', token, hint)

    def _token_request(self, form):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
        self._authenticate(form, headers)

        return self._request(self.config['token_endpoint'],
                             data=urllib.parse.urlencode(form).encode(), headers=headers)

    def _token_action(self, endpoint, token, hint):
        url = discovery.endpoint_url(self.config, endpoint)
        form = {'token': token, 'token_type_hint': hint, 'client_id': self.client_id}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
        self._authenticate(form, headers)

        return self._request(url, data=urllib.parse.urlencode(form).encode(), headers=headers)

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

    @staticmethod
    def _request(url, data=None, headers=None):
        request = urllib.request.Request(url, data=data, headers=headers or {})

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return OidcClient._parse(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read().decode('utf-8', 'replace').strip()
            raise ProviderRequestError(
                f'{url} -> HTTP {error.code} {error.reason}\n{detail}') from error
        except urllib.error.URLError as error:
            raise ProviderRequestError(f'{url} -> {error.reason}') from error

    @staticmethod
    def _parse(body):
        if not body.strip():
            return {}

        try:
            return json.loads(body)
        except ValueError:
            return {'response': body.decode('utf-8', 'replace')}
