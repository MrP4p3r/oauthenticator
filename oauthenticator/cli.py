"""Argument parsing: turns argv and OAUTHENTICATOR_* settings into a validated RunConfig.

Settings sources
    A CLI flag wins over the process environment, which wins over the env
    file (--env-file, .env in the current directory by default), which wins
    over the built-in default. Only the connection settings have an
    OAUTHENTICATOR_* variable; per-run switches stay flag-only. An empty
    variable still hides the sources below it, then falls back to the
    built-in default, or to no value at all.

Redirect URI
    An explicit redirect URI, from any source, is used as is. Otherwise it is
    built from the host and port as http://<host>:<port>/callback.

Scopes
    --scope replaces the base set, --add-scope appends to whatever the base
    ended up being, so a provider specific scope needs no retyping of the
    openid defaults. Repeats and duplicates collapse in first seen order.
    A refresh_token usually needs --add-scope offline_access; Google instead
    wants authorization parameters this tool does not send yet.
    OAUTHENTICATOR_ADD_SCOPE is appended first, then every --add-scope.
"""

import argparse
import os
import sys
from pathlib import Path

from dotenv import dotenv_values

from oauthenticator.config import RunConfig

DESCRIPTION = 'Prototype CLI for the OAuth2/OIDC authorization code flow.'
ENV_PREFIX = 'OAUTHENTICATOR_'
DEFAULT_ENV_FILE = '.env'
DEFAULT_SCOPE = 'openid email profile'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 8765
CALLBACK_PATH = '/callback'
DEFAULT_IDLE_TIMEOUT = 120.0


def parse_args(argv=None, environ=None):
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.env_file is not None and not Path(args.env_file).exists():
        parser.error(f'env file not found: {args.env_file}')

    env_file = Path(args.env_file or DEFAULT_ENV_FILE)
    settings = _read_settings(env_file, os.environ if environ is None else environ)

    try:
        config = _build_config(args, settings)
    except ValueError as error:
        parser.error(str(error))

    if not config.has_valid_redirect_uri:
        sys.exit('the redirect URI must look like http://localhost:8765/callback')

    return config


def _build_parser():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--env-file', metavar='PATH',
                        help=f'read {ENV_PREFIX}* settings from this file '
                             f'(default: {DEFAULT_ENV_FILE} in the current directory, if present)')
    parser.add_argument('--issuer', help=f'OIDC issuer base URL (env: {ENV_PREFIX}ISSUER)')
    parser.add_argument('--client-id', help=f'env: {ENV_PREFIX}CLIENT_ID')
    parser.add_argument('--client-secret',
                        help=f'omit for a public client (env: {ENV_PREFIX}CLIENT_SECRET)')
    parser.add_argument('--scope',
                        help=f'replaces the base scope set '
                             f'(default: {DEFAULT_SCOPE}; env: {ENV_PREFIX}SCOPE)')
    parser.add_argument('--add-scope', action='append', default=[], metavar='SCOPE',
                        help=f'append to the base scope set, repeatable, may be space separated '
                             f'(env: {ENV_PREFIX}ADD_SCOPE)')
    parser.add_argument('--redirect-uri',
                        help=f'must be registered at the provider; overrides --host and --port '
                             f'(default: built from them; env: {ENV_PREFIX}REDIRECT_URI)')
    parser.add_argument('--host',
                        help=f'redirect URI host when no redirect URI is given '
                             f'(default: {DEFAULT_HOST}; env: {ENV_PREFIX}HOST)')
    parser.add_argument('--port', type=int,
                        help=f'redirect URI port when no redirect URI is given '
                             f'(default: {DEFAULT_PORT}; env: {ENV_PREFIX}PORT)')
    parser.add_argument('--no-browser', action='store_true',
                        help='do not open a browser; the URL is printed either way')
    parser.add_argument('--stdout', action='store_true',
                        help='dump the result to the terminal and exit instead of serving a page')
    parser.add_argument('--idle-timeout', type=float, default=DEFAULT_IDLE_TIMEOUT,
                        metavar='SECONDS',
                        help='exit this long after the last ping from the page '
                             '(default: %(default)s)')
    parser.add_argument('--post-logout-redirect', metavar='URI',
                        help='where the provider sends the browser after ending the session, '
                             'omitted by default since it must be registered '
                             f'(env: {ENV_PREFIX}POST_LOGOUT_REDIRECT)')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='repeatable: -v warning, -vv info, -vvv debug '
                             '(default: errors only, applies to uvicorn too)')

    return parser


def _read_settings(env_file, environ):
    """OAUTHENTICATOR_* values keyed without the prefix, the process environment winning."""
    file_values = dotenv_values(env_file) if env_file.exists() else {}

    return {**_strip_prefix(file_values), **_strip_prefix(environ)}


def _strip_prefix(values):
    return {name.removeprefix(ENV_PREFIX): value for name, value in values.items()
            if name.startswith(ENV_PREFIX) and value is not None}


def _build_config(args, settings):
    issuer = _pick(args.issuer, settings, 'ISSUER')
    client_id = _pick(args.client_id, settings, 'CLIENT_ID')

    if issuer is None:
        raise ValueError(f'--issuer or {ENV_PREFIX}ISSUER is required')

    if client_id is None:
        raise ValueError(f'--client-id or {ENV_PREFIX}CLIENT_ID is required')

    base_scope = _pick(args.scope, settings, 'SCOPE', DEFAULT_SCOPE)
    add_scope = args.add_scope
    if 'ADD_SCOPE' in settings:
        add_scope = [settings['ADD_SCOPE'], *add_scope]

    return RunConfig(
        issuer=issuer, client_id=client_id,
        client_secret=_pick(args.client_secret, settings, 'CLIENT_SECRET'),
        scope=_merge_scopes(base_scope, add_scope),
        redirect_uri=_build_redirect_uri(args, settings),
        no_browser=args.no_browser, stdout=args.stdout, idle_timeout=args.idle_timeout,
        post_logout_redirect=_pick(args.post_logout_redirect, settings, 'POST_LOGOUT_REDIRECT'),
        verbosity=args.verbose)


def _build_redirect_uri(args, settings):
    redirect_uri = _pick(args.redirect_uri, settings, 'REDIRECT_URI')
    host = _pick(args.host, settings, 'HOST')
    port = _pick(args.port, settings, 'PORT')

    if redirect_uri is not None:
        if host is not None or port is not None:
            print(f'warning: host and port are ignored, the redirect URI {redirect_uri} wins',
                  file=sys.stderr)

        return redirect_uri

    return f'http://{host or DEFAULT_HOST}:{_parse_port(port)}{CALLBACK_PATH}'


def _parse_port(port):
    if port is None:
        return DEFAULT_PORT

    try:
        return int(port)
    except ValueError:
        raise ValueError(f'{ENV_PREFIX}PORT must be a number, got {port!r}') from None


def _pick(cli_value, settings, name, default=None):
    if cli_value is not None:
        return cli_value

    return settings.get(name) or default


def _merge_scopes(base_scope, add_scope):
    scopes = base_scope.split()
    for value in add_scope:
        scopes.extend(value.split())

    return ' '.join(dict.fromkeys(scopes))
