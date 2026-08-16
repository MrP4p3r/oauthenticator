"""Argument parsing: turns argv into a validated RunConfig.

Scopes
    --scope replaces the base set, --add-scope appends to whatever the base
    ended up being, so a provider specific scope needs no retyping of the
    openid defaults. Repeats and duplicates collapse in first seen order.
    A refresh_token usually needs --add-scope offline_access; Google instead
    wants authorization parameters this tool does not send yet.
"""

import argparse
import sys

from oauthenticator.config import RunConfig

DESCRIPTION = 'Prototype CLI for the OAuth2/OIDC authorization code flow.'
DEFAULT_SCOPE = 'openid email profile'
DEFAULT_REDIRECT_URI = 'http://localhost:8765/callback'
DEFAULT_IDLE_TIMEOUT = 120.0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--issuer', required=True, help='OIDC issuer base URL')
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--client-secret', help='omit for a public client')
    parser.add_argument('--scope', default=DEFAULT_SCOPE,
                        help='replaces the base scope set (default: %(default)s)')
    parser.add_argument('--add-scope', action='append', default=[], metavar='SCOPE',
                        help='append to the base scope set, repeatable, may be space separated')
    parser.add_argument('--redirect-uri', default=DEFAULT_REDIRECT_URI,
                        help='must be registered at the provider (default: %(default)s)')
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
                             'omitted by default since it must be registered')

    args = parser.parse_args(argv)

    config = RunConfig(
        issuer=args.issuer, client_id=args.client_id, client_secret=args.client_secret,
        scope=_merge_scopes(args.scope, args.add_scope), redirect_uri=args.redirect_uri,
        no_browser=args.no_browser, stdout=args.stdout, idle_timeout=args.idle_timeout,
        post_logout_redirect=args.post_logout_redirect)

    if not config.has_valid_redirect_uri:
        sys.exit('--redirect-uri must look like http://localhost:8765/callback')

    return config


def _merge_scopes(base_scope, add_scope):
    scopes = base_scope.split()
    for value in add_scope:
        scopes.extend(value.split())

    return ' '.join(dict.fromkeys(scopes))
