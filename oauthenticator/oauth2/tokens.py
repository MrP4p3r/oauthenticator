"""Token set helpers and expiry math."""

from oauthenticator.oauth2.jwt import Jwt

TIME_FORMAT = '%Y-%m-%d %H:%M:%S UTC'
TOKEN_NAMES = ('access_token', 'id_token', 'refresh_token')
TIME_CLAIMS = ('iat', 'nbf', 'exp', 'auth_time', 'updated_at')
LIFETIME_FIELDS = {'access_token': 'expires_in', 'refresh_token': 'refresh_expires_in'}


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


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
