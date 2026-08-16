"""In-memory flow state shared between the HTTP handler and the main thread.

State validation
    The callback is rejected unless its state matches the generated one,
    which keeps a stray or forged redirect from triggering a token exchange.
    The exchange runs once per session; a page reload re-renders the stored
    result.

Session lifetime
    The page pings every few seconds and the CLI exits once the last ping is
    older than idle_timeout, which tolerates reloads and navigation. The
    default idle timeout is generous because browsers throttle background
    tabs to about one timer callback a minute. Finishing on the page exits
    at once; before the first ping the CLI waits indefinitely, since
    authorization has no deadline.
"""

import secrets
import threading
import time

from oauthenticator.oauth2 import pkce
from oauthenticator.oauth2.errors import OAuth2Error


class AuthSession:
    """Flow state shared between the HTTP handler and the main thread."""

    def __init__(self, client, redirect_uri, scope, idle_timeout, post_logout_redirect):
        self.client = client
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.idle_timeout = idle_timeout
        self.post_logout_redirect = post_logout_redirect
        self.state = secrets.token_urlsafe(24)
        self.nonce = secrets.token_urlsafe(24)
        self.code_verifier = pkce.generate_code_verifier()
        self.action_token = secrets.token_urlsafe(24)
        self.tokens = None
        self.received_at = None
        self.userinfo = None
        self.userinfo_error = None
        self.revoked = set()
        self.error = None
        self.error_params = {}
        self.finished = threading.Event()
        self.delivered = threading.Event()

        self._lock = threading.Lock()
        self._handled = False
        self._last_ping = None

    @property
    def code_challenge(self):
        return pkce.code_challenge(self.code_verifier)

    def authorization_url(self):
        return self.client.authorization_url(
            self.redirect_uri, self.scope, self.state, self.nonce, self.code_challenge)

    def end_session_url(self):
        id_token = (self.tokens or {}).get('id_token')

        return self.client.end_session_url(
            id_token if isinstance(id_token, str) else None, self.post_logout_redirect)

    def complete(self, query):
        with self._lock:
            if self._handled:
                return

            self._handled = True

            if 'error' in query:
                self.error_params = {key: query[key][0] for key in
                                     ('error', 'error_description', 'error_uri') if key in query}
                description = query.get('error_description', [''])[0]
                self.error = f'{query["error"][0]}: {description}'.strip(': ')
                return

            if query.get('state', [None])[0] != self.state:
                self.error = 'state mismatch, ignoring the callback'
                return

            if 'code' not in query:
                self.error = 'no code in the callback query'
                return

            code = query['code'][0]

        try:
            issued = self.client.exchange_code(code, self.redirect_uri, self.code_verifier)
        except OAuth2Error as error:
            with self._lock:
                self.error = str(error)
            return

        self._store(issued)
        self.load_userinfo()

    def refresh(self):
        issued = self.client.refresh(self.token_value('refresh_token'))

        self._store(issued)
        self.load_userinfo()

        return issued

    def load_userinfo(self):
        try:
            self.userinfo = self.client.userinfo(self.token_value('access_token'))
            self.userinfo_error = None
        except (OAuth2Error, RuntimeError) as error:
            self.userinfo = None
            self.userinfo_error = str(error)

    def introspect(self, name):
        return self.client.introspect(self.token_value(name), AuthSession._hint(name))

    def revoke(self, name):
        result = self.client.revoke(self.token_value(name), AuthSession._hint(name))

        with self._lock:
            self.revoked.add(name)

        return result

    def token_value(self, name):
        value = (self.tokens or {}).get(name)
        if not isinstance(value, str):
            raise RuntimeError(f'no {name} in the current token set')

        return value

    def ping(self):
        with self._lock:
            self._last_ping = time.monotonic()

    def is_idle(self):
        with self._lock:
            if self._last_ping is None:
                return False

            return time.monotonic() - self._last_ping > self.idle_timeout

    def _store(self, issued):
        with self._lock:
            self.tokens = {**(self.tokens or {}), **issued}
            self.received_at = time.time()
            self.revoked.clear()

    @staticmethod
    def _hint(name):
        return 'refresh_token' if name == 'refresh_token' else 'access_token'
