"""Identity extraction from a token set."""

from oauthenticator.oauth2.jwt import Jwt
from oauthenticator.oauth2.tokens import is_number


class Identity:
    """Who the tokens are about, read from whichever one carries claims."""

    NAME_CLAIMS = ('name', 'preferred_username', 'nickname', 'email', 'sub')

    def __init__(self, source, claims):
        self.source = source
        self.claims = claims

    @classmethod
    def from_tokens(cls, tokens):
        for name in ('id_token', 'access_token'):
            value = (tokens or {}).get(name)
            decoded = Jwt.decode(value) if isinstance(value, str) else None
            if decoded is not None:
                return cls(name, decoded['payload'])

        return cls(None, {})

    @property
    def name(self):
        given_and_family = ' '.join(
            self.claims[key] for key in ('given_name', 'family_name')
            if isinstance(self.claims.get(key), str))

        candidates = [self.claim(key) for key in Identity.NAME_CLAIMS]
        candidates.insert(1, given_and_family or None)

        for candidate in candidates:
            if candidate is not None:
                return candidate

        return 'Unknown user'

    @property
    def email(self):
        return self.claim('email')

    @property
    def email_verified(self):
        return self.claims.get('email_verified') is True

    @property
    def picture(self):
        return self.claim('picture')

    @property
    def expires_at(self):
        expiry = self.claims.get('exp')

        return expiry if is_number(expiry) else None

    def claim(self, key):
        value = self.claims.get(key)

        return value if isinstance(value, str) and value else None
