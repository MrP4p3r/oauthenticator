#!/usr/bin/env python3
"""Composition root: builds every runtime object and drives the CLI flow."""

import asyncio
import sys

import httpx
import uvicorn

from oauthenticator.cli import parse_args
from oauthenticator.oauth2.client import OidcClient
from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.state.session import AuthSession
from oauthenticator.ui.terminal import report, startup
from oauthenticator.web.app import create_app

REQUEST_TIMEOUT = 30.0


async def run(config):
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as http_client:
        client = OidcClient(http_client, config.issuer, config.client_id, config.client_secret)

        try:
            discovered = await client.discover()
        except OAuth2Error as error:
            sys.exit(str(error))

        startup.print_endpoints(discovered)

        session = AuthSession(client, config.redirect_uri, config.scope, config.idle_timeout,
                              config.post_logout_redirect)

        redirect = config.redirect
        app = create_app(session, redirect.path or '/', config.stdout)
        server = uvicorn.Server(uvicorn.Config(
            app, host=redirect.hostname, port=redirect.port,
            log_level='error', access_log=False))
        server_task = asyncio.create_task(server.serve())

        while not server.started:
            await asyncio.sleep(0.01)

        url = session.authorization_url()
        startup.open_browser(url, config.no_browser)

        try:
            await _wait_until_done(session, config)
        except KeyboardInterrupt:
            pass
        finally:
            server.should_exit = True
            await server_task

        if session.error is not None:
            print('\nerror:', session.error, file=sys.stderr)
            return 1

        if config.stdout and session.tokens is not None:
            report.print_result(session)

        return 0


async def _wait_until_done(session, config):
    """Watchdog: waits for finish, for idle, or (in --stdout mode) for delivery."""
    while not session.finished.is_set() and not session.is_idle():
        if config.stdout and session.delivered.is_set():
            return

        await asyncio.sleep(0.2)


def main():
    config = parse_args()

    return asyncio.run(run(config))


if __name__ == '__main__':
    sys.exit(main())
