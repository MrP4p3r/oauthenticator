"""--stdout dump of the session result.

With --stdout the callback page only asks to be closed and the whole result
is dumped to the terminal here instead, each token raw on its own line.
"""

import json
import time

from oauthenticator.oauth2.identity import Identity
from oauthenticator.oauth2.jwt import Jwt
from oauthenticator.oauth2.tokens import TIME_FORMAT


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
