#!/usr/bin/env python3
"""
Prototype CLI for the OAuth2/OIDC authorization code flow.

Discovers the provider config, opens the authorization URL in a browser,
catches the callback on a local HTTP server and shows the tokens together
with their decoded JWT parts. Stays alive while the page is open so the
issued tokens can be refreshed, introspected and revoked from it.

Discovery
    Reads <issuer>/.well-known/openid-configuration and takes the endpoints
    from there, so only --issuer is needed instead of a per-provider list of
    URLs. Fails early when authorization_endpoint or token_endpoint is absent.
    The userinfo, introspection and revocation endpoints are optional: the
    page offers each action only when the provider advertises it.

Callback server
    A local ThreadingHTTPServer bound to the host and port of --redirect-uri
    catches the redirect, since a CLI has no other way to receive the code.
    It also serves the result page, its ping and its action endpoints, so it
    has to be threaded: actions run while other requests are in flight.

PKCE and nonce
    Every authorization request carries an S256 code_challenge and a nonce.
    They cost nothing here and are mandatory at a growing number of providers,
    so the tool also works for public clients (--client-secret omitted).

Scopes
    --scope replaces the base set, --add-scope appends to whatever the base
    ended up being, so a provider specific scope needs no retyping of the
    openid defaults. Repeats and duplicates collapse in first seen order.
    A refresh_token usually needs --add-scope offline_access; Google instead
    wants authorization parameters this tool does not send yet.

Client authentication
    With a secret the token request uses client_secret_basic, falling back to
    client_secret_post when discovery advertises only that method. Basic
    credentials are form-urlencoded first, as RFC 6749 requires. The same
    choice applies to the refresh, introspection and revocation calls.

State validation
    The callback is rejected unless its state matches the generated one, which
    keeps a stray or forged redirect from triggering a token exchange. The
    exchange runs once per session; a page reload re-renders the stored result.

Result page
    An identity card built from the id_token, or from the access_token when
    that is a JWT too, heads the page and falls back to sub alone when no name
    claims are present. Below it one tab per token plus a userinfo tab, each
    token collapsed to a single line with expand, copy and live countdown.
    Decoding is unverified base64url — no key material is fetched, so it is
    for inspection only, never for trust.

Page actions
    Refresh replaces the whole token set, so it sits in the top bar instead of
    a single token tab and reloads the page; userinfo, introspection and
    revocation only report on what exists and render in place, next to the
    token they act on. Revocation asks for confirmation and marks the token
    afterwards.
    Every action POST carries a per-session action token, which stops another
    origin from driving these endpoints on a known localhost port.

Ending the session
    Revocation kills tokens, not the login: the provider still recognises the
    browser and hands out a new grant without a prompt. Ending the session is
    RP-initiated logout instead, a front-channel redirect to
    end_session_endpoint with id_token_hint, so the button opens it in a new
    tab and leaves the result page pinging. --post-logout-redirect is off by
    default because providers reject the parameter unless it is registered.

Session lifetime
    The page pings every few seconds and the CLI exits once the last ping is
    older than --idle-timeout, which tolerates reloads and navigation. The
    default is generous because browsers throttle background tabs to about one
    timer callback a minute. Finish on the page exits at once; before the first
    ping the CLI waits indefinitely, since authorization has no deadline.

Output modes
    By default nothing but the endpoints and the authorization URL reaches
    stdout and the browser is the interface. The URL is printed whether or not
    the browser opens, so it can be copied to another machine or reopened after
    the tab is lost. With --stdout the callback page only asks to be closed and
    the whole result is dumped to the terminal, each token raw on its own line.
"""

import argparse
import base64
from functools import partial
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

DISCOVERY_PATH = '/.well-known/openid-configuration'
PING_PATH = '/ping'
FINISH_PATH = '/finish'
REFRESH_PATH = '/refresh'
USERINFO_PATH = '/userinfo'
INTROSPECT_PATH = '/introspect'
REVOKE_PATH = '/revoke'
PING_INTERVAL = 5
IDLE_TIMEOUT = 120.0
TIME_FORMAT = '%Y-%m-%d %H:%M:%S UTC'


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class Jwt:
    """Unverified decoding of a compact JWS token."""

    @staticmethod
    def decode(token):
        parts = token.split('.')
        if len(parts) != 3:
            return None

        try:
            header = Jwt._decode_segment(parts[0])
            payload = Jwt._decode_segment(parts[1])
        except ValueError:
            return None

        return {'header': header, 'payload': payload, 'signature': parts[2]}

    @staticmethod
    def _decode_segment(segment):
        padded = segment + '=' * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode()))


class Identity:
    """Who the tokens are about, read from whichever one carries claims."""

    NAME_CLAIMS = ('name', 'preferred_username', 'nickname', 'email', 'sub')

    def __init__(self, source, claims):
        self.source = source
        self.claims = claims

    @classmethod
    def from_tokens(cls, tokens):
        for name in ('id_token', 'access_token'):
            value = (tokens or {}).get(name)
            decoded = Jwt.decode(value) if isinstance(value, str) else None
            if decoded is not None:
                return cls(name, decoded['payload'])

        return cls(None, {})

    @property
    def name(self):
        given_and_family = ' '.join(
            self.claims[key] for key in ('given_name', 'family_name')
            if isinstance(self.claims.get(key), str))

        candidates = [self.claim(key) for key in Identity.NAME_CLAIMS]
        candidates.insert(1, given_and_family or None)

        for candidate in candidates:
            if candidate is not None:
                return candidate

        return 'Unknown user'

    @property
    def email(self):
        return self.claim('email')

    @property
    def email_verified(self):
        return self.claims.get('email_verified') is True

    @property
    def picture(self):
        return self.claim('picture')

    @property
    def expires_at(self):
        expiry = self.claims.get('exp')

        return expiry if is_number(expiry) else None

    def claim(self, key):
        value = self.claims.get(key)

        return value if isinstance(value, str) and value else None


class OidcClient:
    """Talks to the provider: discovery, authorization URL, token operations."""

    def __init__(self, issuer, client_id, client_secret):
        self.issuer = issuer.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.config = {}

    def discover(self):
        url = self.issuer + DISCOVERY_PATH
        self.config = self._request(url)

        for key in ('authorization_endpoint', 'token_endpoint'):
            if key not in self.config:
                raise RuntimeError(f'{key} is missing in {url}')

        return self.config

    def supports(self, endpoint):
        return isinstance(self.config.get(endpoint), str)

    def authorization_url(self, redirect_uri, scope, state, nonce, code_challenge):
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
        }
        separator = '&' if '?' in self.config['authorization_endpoint'] else '?'

        return self.config['authorization_endpoint'] + separator + urllib.parse.urlencode(params)

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
        url = self._endpoint('userinfo_endpoint')
        headers = {'Authorization': 'Bearer ' + access_token, 'Accept': 'application/json'}

        return self._request(url, headers=headers)

    def end_session_url(self, id_token, post_logout_redirect):
        url = self._endpoint('end_session_endpoint')
        params = {'client_id': self.client_id}

        if id_token is not None:
            params['id_token_hint'] = id_token
        if post_logout_redirect is not None:
            params['post_logout_redirect_uri'] = post_logout_redirect

        separator = '&' if '?' in url else '?'

        return url + separator + urllib.parse.urlencode(params)

    def introspect(self, token, hint):
        return self._token_action('introspection_endpoint', token, hint)

    def revoke(self, token, hint):
        return self._token_action('revocation_endpoint', token, hint)

    def _endpoint(self, name):
        url = self.config.get(name)
        if not isinstance(url, str):
            raise RuntimeError(f'{name} is missing in the discovery document')

        return url

    def _token_request(self, form):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }
        self._authenticate(form, headers)

        return self._request(self.config['token_endpoint'],
                             data=urllib.parse.urlencode(form).encode(), headers=headers)

    def _token_action(self, endpoint, token, hint):
        url = self._endpoint(endpoint)
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
            raise RuntimeError(f'{url} -> HTTP {error.code} {error.reason}\n{detail}') from error
        except urllib.error.URLError as error:
            raise RuntimeError(f'{url} -> {error.reason}') from error

    @staticmethod
    def _parse(body):
        if not body.strip():
            return {}

        try:
            return json.loads(body)
        except ValueError:
            return {'response': body.decode('utf-8', 'replace')}


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
        self.code_verifier = secrets.token_urlsafe(64)
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
        digest = hashlib.sha256(self.code_verifier.encode()).digest()

        return base64.urlsafe_b64encode(digest).decode().rstrip('=')

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
        except RuntimeError as error:
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
        except RuntimeError as error:
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


class ResultPage:
    """Renders the page shown in the browser after the callback."""

    TOKEN_NAMES = ('access_token', 'id_token', 'refresh_token')
    TIME_CLAIMS = ('iat', 'nbf', 'exp', 'auth_time', 'updated_at')
    LIFETIME_FIELDS = {'access_token': 'expires_in', 'refresh_token': 'refresh_expires_in'}
    CURL_FALLBACK = 'https://api.example.com/resource'

    TEMPLATE = string.Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>oauthenticator</title>
<style>
:root {
  --bg: #fff; --fg: #1b1b1b; --muted: #666; --line: #ddd; --panel: #f4f4f4;
  --raised: #fafafa; --danger: #a00; --ok: #070;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #16181c; --fg: #e4e4e4; --muted: #9aa1a9; --line: #333941; --panel: #1d2025;
    --raised: #1a1d21; --danger: #ff7b72; --ok: #7ee787;
  }
}
html { scrollbar-gutter: stable; }
body { font-family: sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem;
       background: var(--bg); color: var(--fg); }
h1 { font-size: 1.2rem; }
h3 { font-size: 0.85rem; text-transform: uppercase; color: var(--muted);
     margin: 1.2rem 0 0.3rem; }
pre { background: var(--panel); padding: 0.6rem; overflow-x: auto; font-size: 0.8rem;
      border-radius: 0.3rem; }
.note { color: var(--muted); font-size: 0.85rem; }
.mono { font-family: monospace; }
.failed { color: var(--danger); }
.expired { color: var(--danger); font-weight: 600; }

.bar { display: flex; align-items: center; gap: 0.8rem; }
.bar .note { flex: 1; margin: 0; }

button { font: inherit; font-size: 0.85rem; color: var(--fg); cursor: pointer;
         background: var(--raised); border: 1px solid var(--line); border-radius: 0.3rem;
         padding: 0.3rem 0.7rem; }
button:hover:not(:disabled) { border-color: var(--muted); }
button:disabled { color: var(--muted); cursor: default; }
button.danger { color: var(--danger); }

.identity { display: flex; align-items: center; gap: 0.9rem; margin-top: 1.5rem;
            border: 1px solid var(--line); border-radius: 0.5rem; padding: 0.8rem 1rem; }
.identity img { width: 3rem; height: 3rem; border-radius: 50%; object-fit: cover; }
.identity .who { flex: 1; min-width: 0; }
.identity .name { font-size: 1.05rem; font-weight: 600; }
.identity .line { color: var(--muted); font-size: 0.85rem; overflow-wrap: anywhere; }
.identity .badge { background: var(--panel); color: var(--muted); border-radius: 1rem;
                   padding: 0.15rem 0.6rem; font-size: 0.75rem; white-space: nowrap; }

.meta { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.6rem; }
.meta .chip { background: var(--panel); color: var(--muted); border-radius: 0.3rem;
              padding: 0.2rem 0.5rem; font-size: 0.8rem; }

.tabs { display: flex; gap: 0.3rem; border-bottom: 1px solid var(--line); margin-top: 1.5rem; }
.tabs button { background: none; border-color: transparent; border-bottom: none;
               border-radius: 0.4rem 0.4rem 0 0; padding: 0.5rem 0.9rem;
               font-size: 0.9rem; color: var(--muted); margin-bottom: -1px; }
.tabs button::after { content: attr(data-tab); display: block; height: 0; overflow: hidden;
                      font-weight: 600; visibility: hidden; }
.tabs button:hover:not(.active) { background: var(--panel); border-color: transparent;
                                  box-shadow: inset 0 -1px var(--line); }
.tabs button.active { border-color: var(--line); background: var(--bg); color: var(--fg);
                      font-weight: 600; }
.panel { display: none; }
.panel.active { display: block; }

.token { display: flex; align-items: flex-start; gap: 0.4rem; margin-top: 1rem;
         background: var(--raised); border: 1px solid var(--line); border-radius: 0.4rem;
         padding: 0.4rem 0.5rem; }
.token .value { flex: 1; min-width: 0; font-family: monospace; font-size: 0.8rem;
                line-height: 1.5; white-space: nowrap; overflow: hidden;
                text-overflow: ellipsis; }
.token.open .value { white-space: pre-wrap; word-break: break-all; }
.token button { background: none; border: none; padding: 0 0.2rem; font-size: 0.9rem;
                line-height: 1.5; }
.panel.revoked .token .value { text-decoration: line-through; opacity: 0.55; }

.times { margin-top: 0.4rem; }
.times .line { color: var(--muted); font-size: 0.8rem; }
.times b { font-family: monospace; color: var(--fg); font-weight: normal; }

.actions { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.6rem; }
.result { white-space: pre-wrap; word-break: break-word; margin-top: 0.6rem; }
</style>
</head>
<body>
<div class="bar">
<h1>$title</h1>
<p class="note">The CLI runs while this page is open.</p>
$session_actions
<button onclick="finish(this)">Finish and exit CLI</button>
</div>
$body
<script>
const ACTION_TOKEN = '$action_token';
let pinger = null;

function post(path, payload) {
  const body = Object.assign({action_token: ACTION_TOKEN}, payload || {});

  return fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  }).then(response => response.json().then(data => {
    if (!response.ok) { throw new Error(data.error || response.statusText); }
    return data;
  }));
}

function ping() { fetch('$ping_path').catch(() => {}); }

function finish(button) {
  button.disabled = true;
  post('$finish_path').then(() => {
    clearInterval(pinger);
    button.textContent = 'CLI stopped';
    document.querySelector('.bar .note').textContent = 'You can close this tab.';
  });
}

function endSession(button) {
  const question = 'Log out at the provider? This ends the single sign-on session '
    + 'for every application using it, not just this one.';

  if (window.confirm(question)) { window.open(button.dataset.url, '_blank', 'noopener'); }
}

function selectTab(name) {
  document.querySelectorAll('[data-tab]').forEach(node => {
    node.classList.toggle('active', node.dataset.tab === name);
  });
  history.replaceState(null, '', '#' + name);
}

function toggleToken(button) {
  const open = button.parentElement.classList.toggle('open');
  button.textContent = open ? '▾' : '▸';
  button.title = open ? 'Collapse' : 'Expand';
}

function copyValue(button) {
  copyText(button.parentElement.querySelector('.value').textContent, button, '📋');
}

function copyCurl(button) {
  copyText(button.dataset.curl, button, 'Copy as curl');
}

function copyText(text, button, restore) {
  const done = () => {
    button.textContent = '✅';
    setTimeout(() => { button.textContent = restore; }, 1000);
  };

  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(done, () => copyBySelection(text, done));
  } else {
    copyBySelection(text, done);
  }
}

function copyBySelection(text, done) {
  const area = document.createElement('textarea');
  area.value = text;
  document.body.appendChild(area);
  area.select();
  document.execCommand('copy');
  area.remove();
  done();
}

function showResult(name, text, failed) {
  const box = document.querySelector('section[data-tab="' + name + '"] .result');
  box.textContent = text;
  box.classList.toggle('failed', Boolean(failed));
  box.hidden = false;
}

function refreshTokens(button) {
  const restore = button.textContent;
  const note = document.querySelector('.bar .note');

  button.disabled = true;
  button.textContent = 'Refreshing...';
  post('$refresh_path').then(
    () => location.reload(),
    error => {
      button.disabled = false;
      button.textContent = restore;
      note.textContent = error.message;
      note.classList.add('failed');
    });
}

function reloadUserinfo() {
  showResult('userinfo', 'fetching...');
  post('$userinfo_path').then(
    data => showResult('userinfo', JSON.stringify(data, null, 2)),
    error => showResult('userinfo', error.message, true));
}

function introspect(name) {
  showResult(name, 'introspecting...');
  post('$introspect_path', {token: name}).then(
    data => showResult(name, JSON.stringify(data, null, 2)),
    error => showResult(name, error.message, true));
}

function revoke(name) {
  if (!window.confirm('Revoke the ' + name + '? This cannot be undone.')) { return; }

  showResult(name, 'revoking...');
  post('$revoke_path', {token: name}).then(
    () => {
      showResult(name, 'revoked');
      document.querySelector('section[data-tab="' + name + '"]').classList.add('revoked');
    },
    error => showResult(name, error.message, true));
}

function tick() {
  const now = Date.now() / 1000;

  document.querySelectorAll('[data-time]').forEach(node => {
    const left = Number(node.dataset.time) - now;
    node.textContent = left >= 0 ? 'in ' + clock(left) : clock(-left) + ' ago';
    node.classList.toggle('expired', left < 0 && 'deadline' in node.dataset);
  });
}

function clock(seconds) {
  const total = Math.floor(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor(total / 60) % 60;
  const rest = String(total % 60).padStart(2, '0');

  return hours > 0 ? hours + 'h ' + minutes + 'm' : minutes + 'm ' + rest + 's';
}

const wanted = location.hash.slice(1);
if (wanted && document.querySelector('section[data-tab="' + wanted + '"]')) { selectTab(wanted); }

tick();
setInterval(tick, 1000);
ping();
pinger = setInterval(ping, $ping_interval * 1000);
addEventListener('visibilitychange', () => { if (!document.hidden) { ping(); } });
</script>
</body>
</html>
""")

    NOTICE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>oauthenticator</title>
<style>
body { font-family: sans-serif; margin: 4rem auto; max-width: 30rem; text-align: center;
       color: #444; }
@media (prefers-color-scheme: dark) { body { background: #16181c; color: #b8bec6; } }
</style>
</head>
<body>
<p>$message</p>
<p>You can close this tab.</p>
<script>window.close();</script>
</body>
</html>
"""

    @staticmethod
    def render(session):
        if session.error is not None:
            title = 'Authorization failed'
            body = ResultPage._render_error(session)
        else:
            title = 'Authorization complete'
            body = ResultPage._render_result(session)

        return ResultPage.TEMPLATE.substitute(
            title=title, body=body, action_token=session.action_token,
            session_actions=ResultPage._render_session_actions(session),
            ping_path=PING_PATH, ping_interval=PING_INTERVAL, finish_path=FINISH_PATH,
            refresh_path=REFRESH_PATH, userinfo_path=USERINFO_PATH,
            introspect_path=INTROSPECT_PATH, revoke_path=REVOKE_PATH).encode()

    @staticmethod
    def render_notice(session):
        message = ('The authorization failed, see the terminal.' if session.error is not None
                   else 'The tokens are in the terminal.')

        return string.Template(ResultPage.NOTICE).substitute(message=message).encode()

    @staticmethod
    def _render_session_actions(session):
        buttons = []

        if isinstance((session.tokens or {}).get('refresh_token'), str):
            buttons.append('<button onclick="refreshTokens(this)">'
                           'Refresh the token set</button>')

        if session.client.supports('end_session_endpoint'):
            url = html.escape(session.end_session_url())
            buttons.append(f'<button class="danger" data-url="{url}" onclick="endSession(this)">'
                           'End provider session</button>')

        return ''.join(buttons)

    @staticmethod
    def _render_error(session):
        params = session.error_params
        headline = params.get('error') or 'The request never reached a token'
        lines = [params.get('error_description') or
                 'nothing was issued, so there is nothing to inspect']

        if 'error_uri' in params:
            lines.append('error_uri ' + params['error_uri'])

        chunks = ['<div class="identity"><div class="who">',
                  f'<div class="name failed">{html.escape(headline)}</div>']
        chunks.extend(f'<div class="line">{html.escape(line)}</div>' for line in lines)
        chunks.append('</div>')

        if params:
            chunks.append('<span class="badge">callback</span>')

        chunks.append('</div>')

        return ''.join(chunks) + f'\n<pre class="result failed">{html.escape(session.error)}</pre>'

    @staticmethod
    def _render_result(session):
        return '\n'.join([
            ResultPage._render_identity(session),
            ResultPage._render_extras(session.tokens),
            ResultPage._render_tabs(session),
        ])

    @staticmethod
    def _render_identity(session):
        identity = Identity.from_tokens(session.tokens)
        if identity.source is None:
            return ('<div class="identity"><div class="who">'
                    '<div class="name">Unknown user</div>'
                    '<div class="line">the response carries no JWT to decode</div>'
                    '</div></div>')

        chunks = ['<div class="identity">']
        if identity.picture is not None:
            chunks.append(f'<img src="{html.escape(identity.picture)}" alt="" '
                          'referrerpolicy="no-referrer" onerror="this.remove()">')

        chunks.append('<div class="who">')
        chunks.append(f'<div class="name">{html.escape(identity.name)}</div>')
        chunks.extend(f'<div class="line">{line}</div>'
                      for line in ResultPage._identity_lines(identity))
        chunks.append('</div>')
        chunks.append(f'<span class="badge">{identity.source}</span>')
        chunks.append('</div>')

        return ''.join(chunks)

    @staticmethod
    def _identity_lines(identity):
        lines = []
        name = identity.name

        if identity.email is not None and identity.email != name:
            verified = ' ✓ verified' if identity.email_verified else ''
            lines.append(html.escape(identity.email) + verified)

        facts = []
        for key in ('sub', 'iss'):
            value = identity.claim(key)
            if value is not None and value != name:
                facts.append(f'{key} <span class="mono">{html.escape(value)}</span>')

        if facts:
            lines.append(' &middot; '.join(facts))

        expiry = ResultPage._render_expiry(identity.expires_at)
        if expiry is not None:
            lines.append(expiry)

        return lines

    @staticmethod
    def _render_expiry(expires_at):
        if expires_at is None:
            return None

        stamp = time.strftime(TIME_FORMAT, time.gmtime(expires_at))

        return (f'expires {stamp} &middot; '
                f'<span data-time="{expires_at:.0f}" data-deadline></span>')

    @staticmethod
    def _render_extras(tokens):
        chips = []

        for name, value in tokens.items():
            if name in ResultPage.TOKEN_NAMES and isinstance(value, str):
                continue

            text = value if isinstance(value, str) else json.dumps(value)
            chips.append(f'<span class="chip"><b>{html.escape(name)}</b> '
                         f'{html.escape(text)}</span>')

        if not chips:
            return ''

        return '<div class="meta">' + ''.join(chips) + '</div>'

    @staticmethod
    def _render_tabs(session):
        names = [name for name in ResultPage.TOKEN_NAMES
                 if isinstance(session.tokens.get(name), str)]
        names.append('userinfo')

        buttons = []
        panels = []
        for index, name in enumerate(names):
            classes = ['panel']
            if index == 0:
                classes.append('active')
            if name in session.revoked:
                classes.append('revoked')

            active = ' class="active"' if index == 0 else ''
            content = (ResultPage._render_userinfo(session) if name == 'userinfo'
                       else ResultPage._render_token(session, name))

            buttons.append(f'<button{active} data-tab="{name}" '
                           f'onclick="selectTab(\'{name}\')">{name}</button>')
            panels.append(f'<section class="{" ".join(classes)}" data-tab="{name}">'
                          + content + '</section>')

        return '<nav class="tabs">' + ''.join(buttons) + '</nav>\n' + '\n'.join(panels)

    @staticmethod
    def _render_token(session, name):
        value = session.tokens[name]
        chunks = [
            '<div class="token">'
            '<button title="Expand" onclick="toggleToken(this)">▸</button>'
            f'<code class="value">{html.escape(value)}</code>'
            '<button title="Copy" onclick="copyValue(this)">📋</button>'
            '</div>'
        ]

        expiry = ResultPage._render_expiry(ResultPage._expires_at(session, name))
        if expiry is not None:
            chunks.append(f'<p class="note">{expiry}</p>')

        chunks.append(ResultPage._render_actions(session, name))
        chunks.append('<pre class="result" hidden></pre>')
        chunks.extend(ResultPage._render_claims(value))

        return '\n'.join(chunks)

    @staticmethod
    def _render_actions(session, name):
        if name == 'id_token':
            return ('<p class="note">An id_token is not an OAuth token: introspection and '
                    'revocation do not apply to it.</p>')

        buttons = []
        if name == 'access_token':
            curl = (session.client.config.get('userinfo_endpoint')
                    or ResultPage.CURL_FALLBACK)
            command = f'curl -H "Authorization: Bearer {session.tokens[name]}" "{curl}"'
            buttons.append(f'<button data-curl="{html.escape(command)}" '
                           'onclick="copyCurl(this)">Copy as curl</button>')

        if session.client.supports('introspection_endpoint'):
            buttons.append(f'<button onclick="introspect(\'{name}\')">Introspect</button>')

        if session.client.supports('revocation_endpoint'):
            buttons.append(f'<button class="danger" onclick="revoke(\'{name}\')">Revoke</button>')

        if not buttons:
            return ''

        return '<div class="actions">' + ''.join(buttons) + '</div>'

    @staticmethod
    def _render_userinfo(session):
        if session.userinfo is not None:
            text = json.dumps(session.userinfo, indent=2)
            failed = ''
        else:
            text = session.userinfo_error or 'not fetched yet'
            failed = ' failed'

        return ('<div class="actions">'
                '<button onclick="reloadUserinfo()">Fetch again</button>'
                '</div>\n'
                f'<pre class="result{failed}">{html.escape(text)}</pre>')

    @staticmethod
    def _expires_at(session, name):
        decoded = Jwt.decode(session.tokens[name])
        if decoded is not None and is_number(decoded['payload'].get('exp')):
            return decoded['payload']['exp']

        lifetime = session.tokens.get(ResultPage.LIFETIME_FIELDS.get(name))
        if is_number(lifetime) and session.received_at is not None:
            return session.received_at + lifetime

        return None

    @staticmethod
    def _render_claims(token):
        decoded = Jwt.decode(token)
        if decoded is None:
            return ['<p class="note">Not a JWT, nothing to decode.</p>']

        header = html.escape(json.dumps(decoded['header'], indent=2))
        payload = html.escape(json.dumps(decoded['payload'], indent=2))
        signature = html.escape(decoded['signature'])

        return [
            f'<h3>header</h3><pre>{header}</pre>',
            f'<h3>payload</h3><pre>{payload}</pre>',
            ResultPage._render_times(decoded['payload']),
            f'<h3>signature</h3><pre>{signature}</pre>',
        ]

    @staticmethod
    def _render_times(payload):
        lines = []

        for claim in ResultPage.TIME_CLAIMS:
            value = payload.get(claim)
            if not is_number(value):
                continue

            stamp = time.strftime(TIME_FORMAT, time.gmtime(value))
            deadline = ' data-deadline' if claim == 'exp' else ''
            lines.append(f'<div class="line"><b>{claim}</b> {stamp} &middot; '
                         f'<span data-time="{value:.0f}"{deadline}></span></div>')

        if not lines:
            return ''

        return '<div class="times">' + ''.join(lines) + '</div>'


class CallbackHandler(BaseHTTPRequestHandler):
    """Serves the callback, the result page, the ping and the page actions."""

    protocol_version = 'HTTP/1.1'

    def __init__(self, session, callback_path, stdout_mode, *args, **kwargs):
        self.session = session
        self.callback_path = callback_path
        self.stdout_mode = stdout_mode
        super().__init__(*args, **kwargs)

    def do_GET(self):
        path, _, query = self.path.partition('?')

        if path == self.callback_path:
            self.session.complete(urllib.parse.parse_qs(query))
            page = (ResultPage.render_notice(self.session) if self.stdout_mode
                    else ResultPage.render(self.session))
            self._send(200, 'text/html; charset=utf-8', page)
            self.session.delivered.set()
        elif path == PING_PATH:
            self.session.ping()
            self._send(200, 'text/plain', b'ok')
        else:
            self._send(404, 'text/plain', b'not found')

    def do_POST(self):
        actions = {
            FINISH_PATH: lambda payload: {'status': 'finished'},
            REFRESH_PATH: lambda payload: self.session.refresh(),
            USERINFO_PATH: self._userinfo,
            INTROSPECT_PATH: lambda payload: self.session.introspect(payload.get('token', '')),
            REVOKE_PATH: lambda payload: self.session.revoke(payload.get('token', '')),
        }
        action = actions.get(self.path)
        if action is None:
            self._send(404, 'text/plain', b'not found')
            return

        payload = self._read_payload()
        if not secrets.compare_digest(str(payload.get('action_token', '')),
                                      self.session.action_token):
            self._send_json(403, {'error': 'bad action token'})
            return

        try:
            result = action(payload)
        except RuntimeError as error:
            self._send_json(502, {'error': str(error)})
            return

        self._send_json(200, result)

        if self.path == FINISH_PATH:
            self.session.finished.set()

    def log_message(self, format, *args):
        pass

    def _userinfo(self, payload):
        self.session.load_userinfo()
        if self.session.userinfo is None:
            raise RuntimeError(self.session.userinfo_error)

        return self.session.userinfo

    def _read_payload(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length == 0:
            return {}

        try:
            payload = json.loads(self.rfile.read(length))
        except ValueError:
            return {}

        return payload if isinstance(payload, dict) else {}

    def _send(self, status, content_type, body):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status, payload):
        self._send(status, 'application/json', json.dumps(payload).encode())


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument('--issuer', required=True, help='OIDC issuer base URL')
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--client-secret', help='omit for a public client')
    parser.add_argument('--scope', default='openid email profile',
                        help='replaces the base scope set (default: %(default)s)')
    parser.add_argument('--add-scope', action='append', default=[], metavar='SCOPE',
                        help='append to the base scope set, repeatable, may be space separated')
    parser.add_argument('--redirect-uri', default='http://localhost:8765/callback',
                        help='must be registered at the provider (default: %(default)s)')
    parser.add_argument('--no-browser', action='store_true',
                        help='do not open a browser; the URL is printed either way')
    parser.add_argument('--stdout', action='store_true',
                        help='dump the result to the terminal and exit instead of serving a page')
    parser.add_argument('--idle-timeout', type=float, default=IDLE_TIMEOUT, metavar='SECONDS',
                        help='exit this long after the last ping from the page '
                             '(default: %(default)s)')
    parser.add_argument('--post-logout-redirect', metavar='URI',
                        help='where the provider sends the browser after ending the session, '
                             'omitted by default since it must be registered')

    args = parser.parse_args()
    scopes = args.scope.split()
    for value in args.add_scope:
        scopes.extend(value.split())

    args.scope = ' '.join(dict.fromkeys(scopes))

    return args


def print_result(session):
    identity = Identity.from_tokens(session.tokens)

    print(f'\n=== identity ({identity.source or "no JWT in the response"}) ===')
    print('name:', identity.name)

    if identity.email is not None:
        print('email:', identity.email + (' (verified)' if identity.email_verified else ''))

    for key in ('sub', 'iss'):
        value = identity.claim(key)
        if value is not None:
            print(f'{key}: {value}')

    if identity.expires_at is not None:
        print('expires:', time.strftime(TIME_FORMAT, time.gmtime(identity.expires_at)))

    for name, value in session.tokens.items():
        print(f'\n=== {name} ===')

        if not isinstance(value, str):
            print(json.dumps(value))
            continue

        print(value)
        decoded = Jwt.decode(value)
        if decoded is None:
            continue

        print('\n--- header ---')
        print(json.dumps(decoded['header'], indent=2))
        print('--- payload ---')
        print(json.dumps(decoded['payload'], indent=2))
        print('--- signature ---')
        print(decoded['signature'])

    print('\n=== userinfo ===')
    print(json.dumps(session.userinfo, indent=2) if session.userinfo is not None
          else session.userinfo_error)


def main():
    args = parse_args()
    redirect = urllib.parse.urlparse(args.redirect_uri)
    if redirect.scheme != 'http' or not redirect.hostname or not redirect.port:
        sys.exit('--redirect-uri must look like http://localhost:8765/callback')

    client = OidcClient(args.issuer, args.client_id, args.client_secret)

    try:
        config = client.discover()
    except RuntimeError as error:
        sys.exit(str(error))

    print('authorization_endpoint:', config['authorization_endpoint'])
    print('token_endpoint:', config['token_endpoint'])

    session = AuthSession(client, args.redirect_uri, args.scope, args.idle_timeout,
                          args.post_logout_redirect)
    handler = partial(CallbackHandler, session, redirect.path or '/', args.stdout)
    server = ThreadingHTTPServer((redirect.hostname, redirect.port), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    url = session.authorization_url()
    print('\nauthorization URL:\n' + url)

    if args.no_browser or not webbrowser.open(url):
        print('\nopen it in a browser, waiting for the callback...')
    else:
        print('\nbrowser opened, waiting for the callback...')

    try:
        while not session.finished.is_set() and not session.is_idle():
            if args.stdout and session.delivered.is_set():
                break

            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()

    if session.error is not None:
        print('\nerror:', session.error, file=sys.stderr)
        return 1

    if args.stdout and session.tokens is not None:
        print_result(session)

    return 0


if __name__ == '__main__':
    sys.exit(main())
