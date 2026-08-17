"""PKCE verifier generation and S256 challenge derivation."""

import re

from oauthenticator.oauth2 import pkce

RFC_7636_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
RFC_7636_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

UNRESERVED = re.compile(r'^[A-Za-z0-9\-._~]+$')


def test_derives_the_rfc_7636_appendix_b_challenge():
    """The published vector pins the transform: SHA-256, base64url, no padding."""
    assert pkce.code_challenge(RFC_7636_VERIFIER) == RFC_7636_CHALLENGE


def test_challenge_is_unpadded_base64url():
    challenge = pkce.code_challenge(pkce.generate_code_verifier())

    assert '=' not in challenge
    assert '+' not in challenge and '/' not in challenge
    assert len(challenge) == 43


def test_challenge_is_stable_for_one_verifier():
    verifier = pkce.generate_code_verifier()

    assert pkce.code_challenge(verifier) == pkce.code_challenge(verifier)


def test_verifier_is_unreserved_and_within_the_rfc_length_bounds():
    verifier = pkce.generate_code_verifier()

    assert UNRESERVED.match(verifier)
    assert 43 <= len(verifier) <= 128


def test_verifiers_do_not_repeat():
    verifiers = {pkce.generate_code_verifier() for _ in range(50)}

    assert len(verifiers) == 50
