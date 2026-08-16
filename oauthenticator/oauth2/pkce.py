"""PKCE code verifier generation and challenge derivation.

Every authorization request carries an S256 code_challenge and a nonce. They
cost nothing here and are mandatory at a growing number of providers, so the
tool also works for public clients (no client secret configured). The session
generates the verifier once per flow and keeps holding it; this module only
derives the verifier and the challenge computed from it.
"""

import base64
import hashlib
import secrets


def generate_code_verifier():
    return secrets.token_urlsafe(64)


def code_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode()).digest()

    return base64.urlsafe_b64encode(digest).decode().rstrip('=')
