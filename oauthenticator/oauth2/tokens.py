"""Token set helpers and expiry math."""

from oauthenticator.oauth2.jwt import Jwt

TIME_FORMAT = '%Y-%m-%d %H:%M:%S UTC'
TOKEN_NAMES = ('access_token', 'id_token', 'refresh_token')
START_CLAIMS = ('iat', 'nbf')
LIFETIME_FIELDS = {'access_token': 'expires_in', 'refresh_token': 'refresh_expires_in'}


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def issued_at(tokens, name, received_at):
    """When one token's life began, with a label naming where that came from.

    Falls back to the moment the token set arrived, so an opaque token -- which
    carries no claims at all but still has a lifetime worth drawing -- gets a
    start too. The label says which it was, since 'recv' is our observation
    while 'iat' is the provider's assertion.
    """
    decoded = Jwt.decode(tokens[name])
    if decoded is not None:
        for claim in START_CLAIMS:
            if is_number(decoded['payload'].get(claim)):
                return decoded['payload'][claim], claim

    return received_at, 'recv'


def expires_at(tokens, name, received_at):
    """The expiry instant for one token in a token set.

    Taken from its exp claim when it decodes as a JWT, otherwise computed
    from the matching lifetime field (expires_in / refresh_expires_in) plus
    the time the token set was issued.
    """
    decoded = Jwt.decode(tokens[name])
    if decoded is not None and is_number(decoded['payload'].get('exp')):
        return decoded['payload']['exp']

    lifetime = tokens.get(LIFETIME_FIELDS.get(name))
    if is_number(lifetime) and received_at is not None:
        return received_at + lifetime

    return None
