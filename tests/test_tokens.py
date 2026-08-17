"""oauth2/tokens.py -- expiry math, computed from a JWT's exp or from a lifetime field."""

from oauthenticator.oauth2.tokens import expires_at, is_number


def test_is_number_excludes_booleans():
    assert is_number(1) is True
    assert is_number(1.5) is True
    assert is_number(True) is False
    assert is_number(False) is False
    assert is_number('1') is False
    assert is_number(None) is False


def test_expires_at_prefers_the_exp_claim_when_the_token_is_a_jwt(token_signer):
    access_token = token_signer.sign({'sub': 'u1', 'exp': 1700000000})
    tokens = {'access_token': access_token, 'expires_in': 60}

    assert expires_at(tokens, 'access_token', received_at=1600000000) == 1700000000


def test_expires_at_falls_back_to_the_lifetime_field_for_opaque_tokens():
    tokens = {'access_token': 'opaque', 'expires_in': 300}

    assert expires_at(tokens, 'access_token', received_at=1000) == 1300


def test_expires_at_uses_refresh_expires_in_for_the_refresh_token():
    tokens = {'refresh_token': 'opaque', 'refresh_expires_in': 86400}

    assert expires_at(tokens, 'refresh_token', received_at=1000) == 87400


def test_expires_at_is_none_without_a_lifetime_or_received_at():
    assert expires_at({'access_token': 'opaque'}, 'access_token', received_at=1000) is None
    assert expires_at({'access_token': 'opaque', 'expires_in': 300}, 'access_token',
                      received_at=None) is None
