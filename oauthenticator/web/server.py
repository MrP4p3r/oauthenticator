"""HTTP interface: catches the callback, serves the result page, ping and page actions.

Callback server
    A local ThreadingHTTPServer bound to the host and port of --redirect-uri
    catches the redirect, since a CLI has no other way to receive the code.
    It also serves the result page, its ping and its action endpoints, so it
    has to be threaded: actions run while other requests are in flight.

Page actions
    Refresh replaces the whole token set, so it sits in the top bar instead
    of a single token tab and reloads the page; userinfo, introspection and
    revocation only report on what exists and render in place, next to the
    token they act on. Every action POST carries a per-session action
    token, which stops another origin from driving these endpoints on a
    known localhost port.
"""

import json
import secrets
import urllib.parse
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.ui.web import renderer, viewmodels
from oauthenticator.ui.web.templates import (
    FINISH_PATH, INTROSPECT_PATH, PING_PATH, REFRESH_PATH, REVOKE_PATH, USERINFO_PATH)


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

            if self.stdout_mode:
                page = renderer.render_notice(viewmodels.build_notice(self.session))
            else:
                page = renderer.render(viewmodels.build_result_page(self.session))

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
        except (OAuth2Error, RuntimeError) as error:
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


def create_server(session, callback_path, stdout_mode, host, port):
    """Builds the callback server. Starting the serving thread is main()'s job."""
    handler = partial(CallbackHandler, session, callback_path, stdout_mode)
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True

    return server
