#!/usr/bin/env python3
"""Composition root: builds every runtime object and drives the CLI flow."""

import sys
import threading
import time

from oauthenticator.cli import parse_args
from oauthenticator.oauth2.client import OidcClient
from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.state.session import AuthSession
from oauthenticator.ui.terminal import report, startup
from oauthenticator.web.server import create_server


def main():
    config = parse_args()

    client = OidcClient(config.issuer, config.client_id, config.client_secret)

    try:
        discovered = client.discover()
    except OAuth2Error as error:
        sys.exit(str(error))

    startup.print_endpoints(discovered)

    session = AuthSession(client, config.redirect_uri, config.scope, config.idle_timeout,
                          config.post_logout_redirect)

    redirect = config.redirect
    server = create_server(session, redirect.path or '/', config.stdout,
                           redirect.hostname, redirect.port)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    url = session.authorization_url()
    startup.open_browser(url, config.no_browser)

    try:
        while not session.finished.is_set() and not session.is_idle():
            if config.stdout and session.delivered.is_set():
                break

            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()

    if session.error is not None:
        print('\nerror:', session.error, file=sys.stderr)
        return 1

    if config.stdout and session.tokens is not None:
        report.print_result(session)

    return 0


if __name__ == '__main__':
    sys.exit(main())
