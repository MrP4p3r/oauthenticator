"""--stdout dump of the session result.

With --stdout the callback page only asks to be closed and the whole result
is dumped to the terminal here instead, each token raw on its own line.

The console passed in is built with soft_wrap on, so no value here is ever
word-wrapped or cropped regardless of the detected width -- this is what
keeps a piped token copyable. Every value that came from the provider (the
identity claims, the tokens themselves) is printed with markup and
highlighting off, so it is never reinterpreted as rich markup or recoloured
by the highlighter; only the JSON payloads go through print_json, which
takes its own safe rendering path and stays valid JSON either way.
"""

import time

from rich.text import Text

from oauthenticator.oauth2.identity import Identity
from oauthenticator.oauth2.jwt import Jwt
from oauthenticator.oauth2.tokens import TIME_FORMAT
from oauthenticator.ui.terminal.rendering import print_field


def print_result(console, session):
    identity = Identity.from_tokens(session.tokens)
    _print_identity(console, identity)

    for name, value in session.tokens.items():
        _print_token(console, name, value)

    console.rule('userinfo')
    if session.userinfo is not None:
        console.print_json(data=session.userinfo)
    else:
        console.print(session.userinfo_error, markup=False, highlight=False)


def _print_identity(console, identity):
    header = identity.source or 'no JWT in the response'
    console.rule(f'identity ({header})')

    print_field(console, 'name', identity.name)

    if identity.email is not None:
        verified = ' (verified)' if identity.email_verified else ''
        print_field(console, 'email', identity.email + verified)

    for key in ('sub', 'iss'):
        value = identity.claim(key)
        if value is not None:
            print_field(console, key, value)

    if identity.expires_at is not None:
        expires = time.strftime(TIME_FORMAT, time.gmtime(identity.expires_at))
        print_field(console, 'expires', expires)


def _print_token(console, name, value):
    console.rule(Text(name))

    if not isinstance(value, str):
        console.print_json(data=value)
        return

    console.print(value, markup=False, highlight=False)

    decoded = Jwt.decode(value)
    if decoded is None:
        return

    console.rule('header', style='dim')
    console.print_json(data=decoded['header'])
    console.rule('payload', style='dim')
    console.print_json(data=decoded['payload'])
    console.rule('signature', style='dim')
    console.print(decoded['signature'], markup=False, highlight=False)
