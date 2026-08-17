"""RSA keypair generation and RS256 signing for the fake OIDC provider.

The keypair itself is built once per test session (see the session-scoped
fixture in conftest.py); this module only holds the generation and the
signer that mints tokens from it. Signing here uses PyJWT -- a JOSE library
is rejected for *decoding* in oauthenticator/oauth2/jwt.py because that code
must tolerate garbage, but minting well-formed tokens for tests is a
different job.
"""

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SIGNING_KEY_ID = 'test-signing-key'
SIGNING_ALGORITHM = 'RS256'


def generate_private_key_pem():
    """A freshly generated RSA private key, PEM-encoded (PKCS8, unencrypted)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())


class TokenSigner:
    """Mints real RS256-signed compact JWTs from one RSA private key."""

    def __init__(self, private_key_pem):
        self.private_key_pem = private_key_pem

    def sign(self, claims):
        return pyjwt.encode(claims, self.private_key_pem, algorithm=SIGNING_ALGORITHM,
                            headers={'kid': SIGNING_KEY_ID})
