#!/usr/bin/env python3
"""Composition root: builds every runtime object and drives the CLI flow."""

import asyncio
import errno
import logging
import re
import socket
import sys

import httpx
import uvicorn
from rich.console import Console
from rich.logging import RichHandler

from oauthenticator.cli import parse_args
from oauthenticator.oauth2.client import OidcClient
from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.state.session import AuthSession
from oauthenticator.ui.terminal import report, startup
from oauthenticator.web.app import create_app

REQUEST_TIMEOUT = 30.0
UVICORN_LOGGERS = ('uvicorn', 'uvicorn.error', 'uvicorn.access', 'uvicorn.asgi')
CALLBACK_CODE_PATTERN = re.compile(r'([?&]code=)[^&\s]*')

logger = logging.getLogger(__name__)


async def run(config):
    _configure_logging(config.log_level)
    _ensure_port_is_free(config.redirect.hostname, config.redirect.port)
    console = Console(soft_wrap=True)

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as http_client:
        client = OidcClient(http_client, config.issuer, config.client_id, config.client_secret)

        try:
            discovered = await client.discover()
        except OAuth2Error as error:
            sys.exit(str(error))

        startup.print_endpoints(console, discovered)

        session = AuthSession(client, config.redirect_uri, config.scope, config.idle_timeout,
                              config.post_logout_redirect)

        redirect = config.redirect
        app = create_app(session, redirect.path or '/', config.stdout)
        server = uvicorn.Server(uvicorn.Config(
            app, host=redirect.hostname, port=redirect.port, log_config=None))

        logger.info('starting server on %s:%s', redirect.hostname, redirect.port)
        server_task = asyncio.create_task(server.serve())

        while not server.started:
            await asyncio.sleep(0.01)

        url = session.authorization_url()
        startup.open_browser(console, url, config.no_browser)

        try:
            await _wait_until_done(session, config)
        except KeyboardInterrupt:
            pass
        finally:
            server.should_exit = True
            await server_task
            logger.info('server stopped')

        if session.error is not None:
            print('\nerror:', session.error, file=sys.stderr)
            return 1

        if config.stdout and session.tokens is not None:
            report.print_result(console, session)

        return 0


def _configure_logging(level):
    """Wires the -v ladder into stdlib logging, rendered through rich on stderr.

    uvicorn builds its own handlers by default (its LOGGING_CONFIG dict),
    which would print access lines straight to stdout regardless of level
    and bypass this formatting entirely -- log_config=None on the
    uvicorn.Config above skips that step, so uvicorn.error/access/asgi
    propagate to this handler instead and are gated by the same level as
    everything else, rather than being configured separately.
    """
    handler = RichHandler(console=Console(stderr=True), show_path=False)
    logging.basicConfig(level=level, format='%(message)s', handlers=[handler], force=True)

    for name in UVICORN_LOGGERS:
        logging.getLogger(name).setLevel(level)

    logging.getLogger('uvicorn.access').addFilter(_redact_authorization_code)


def _redact_authorization_code(record):
    """Strips the authorization code out of one uvicorn access log record.

    uvicorn logs the callback request's raw path and query string, which
    carries the authorization code -- this runs before the record's lazy
    %-formatting, so the code is replaced in record.args before anything
    ever renders it, on this logger alone.
    """
    if record.args and len(record.args) >= 3 and isinstance(record.args[2], str):
        redacted_path = CALLBACK_CODE_PATTERN.sub(r'\1REDACTED', record.args[2])
        record.args = (*record.args[:2], redacted_path, *record.args[3:])

    return True


def _ensure_port_is_free(host, port):
    """Exits with a readable message when the callback port is taken.

    uvicorn reports a bind failure with a traceback and exit code 3, and only
    after discovery has already run, so the port is probed up front with the
    same socket options asyncio's create_server uses.
    """
    for family, kind, protocol, _, address in socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM):
        with socket.socket(family, kind, protocol) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

            try:
                probe.bind(address)
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    sys.exit(f'port {port} is in use; free it or pass --port / --redirect-uri')


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
