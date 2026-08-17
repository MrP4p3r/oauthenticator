"""oauth2/identity.py -- claim extraction and its name/email fallbacks."""

from oauthenticator.oauth2.identity import Identity


def test_from_tokens_prefers_id_token_over_access_token(token_signer):
    id_token = token_signer.sign({'sub': 'from-id-token'})
    access_token = token_signer.sign({'sub': 'from-access-token'})

    identity = Identity.from_tokens({'id_token': id_token, 'access_token': access_token})

    assert identity.source == 'id_token'
    assert identity.claims['sub'] == 'from-id-token'


def test_from_tokens_falls_back_to_access_token_when_it_is_a_jwt(token_signer):
    access_token = token_signer.sign({'sub': 'from-access-token'})

    identity = Identity.from_tokens({'access_token': access_token, 'refresh_token': 'opaque'})

    assert identity.source == 'access_token'
    assert identity.claims['sub'] == 'from-access-token'


def test_from_tokens_has_no_source_when_nothing_decodes_as_a_jwt():
    identity = Identity.from_tokens({'access_token': 'opaque-token', 'refresh_token': 'opaque'})

    assert identity.source is None
    assert identity.claims == {}
    assert identity.name == 'Unknown user'


def test_from_tokens_tolerates_no_tokens_at_all():
    identity = Identity.from_tokens(None)

    assert identity.source is None
    assert identity.claims == {}


def test_name_prefers_the_name_claim():
    identity = Identity('id_token', {'name': 'Ada', 'preferred_username': 'ada', 'sub': 'u1'})

    assert identity.name == 'Ada'


def test_name_falls_back_to_given_and_family_name():
    identity = Identity('id_token', {'given_name': 'Ada', 'family_name': 'Lovelace', 'sub': 'u1'})

    assert identity.name == 'Ada Lovelace'


def test_name_falls_back_to_preferred_username():
    identity = Identity('id_token', {'preferred_username': 'ada', 'sub': 'u1'})

    assert identity.name == 'ada'


def test_name_falls_back_to_email_then_sub():
    assert Identity('id_token', {'email': 'ada@example.com', 'sub': 'u1'}).name == 'ada@example.com'
    assert Identity('id_token', {'sub': 'u1'}).name == 'u1'


def test_name_is_unknown_user_when_no_name_claims_exist():
    identity = Identity('id_token', {'aud': 'client-1'})

    assert identity.name == 'Unknown user'


def test_email_verified_only_when_claim_is_exactly_true():
    assert Identity('id_token', {'email_verified': True}).email_verified is True
    assert Identity('id_token', {'email_verified': 'true'}).email_verified is False
    assert Identity('id_token', {}).email_verified is False


def test_claim_treats_empty_string_as_absent():
    identity = Identity('id_token', {'picture': '', 'email': 'ada@example.com'})

    assert identity.picture is None
    assert identity.email == 'ada@example.com'


def test_expires_at_requires_a_number():
    assert Identity('id_token', {'exp': 1234}).expires_at == 1234
    assert Identity('id_token', {'exp': 'soon'}).expires_at is None
    assert Identity('id_token', {}).expires_at is None
