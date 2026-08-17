"""oauth2/flow.py -- pure front-channel URL builders."""

import urllib.parse

from oauthenticator.oauth2 import flow


def _query(url):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def test_authorization_url_uses_a_question_mark_when_the_endpoint_has_none():
    config = {'authorization_endpoint': 'https://issuer.test/authorize'}

    url = flow.authorization_url(config, 'client-1', 'https://app.test/callback', 'openid',
                                 'state-1', 'nonce-1', 'challenge-1')

    assert url.startswith('https://issuer.test/authorize?')
    query = _query(url)
    assert query['client_id'] == ['client-1']
    assert query['code_challenge_method'] == ['S256']


def test_authorization_url_appends_with_ampersand_when_the_endpoint_already_has_a_query():
    config = {'authorization_endpoint': 'https://issuer.test/authorize?tenant=acme'}

    url = flow.authorization_url(config, 'client-1', 'https://app.test/callback', 'openid',
                                 'state-1', 'nonce-1', 'challenge-1')

    assert url.startswith('https://issuer.test/authorize?tenant=acme&')
    assert _query(url)['tenant'] == ['acme']


def test_end_session_url_includes_id_token_hint_and_post_logout_redirect_when_given():
    url = flow.end_session_url('https://issuer.test/end_session', 'client-1', 'the-id-token',
                               'https://app.test/logged-out')

    query = _query(url)
    assert query['id_token_hint'] == ['the-id-token']
    assert query['post_logout_redirect_uri'] == ['https://app.test/logged-out']


def test_end_session_url_omits_optional_params_when_not_given():
    url = flow.end_session_url('https://issuer.test/end_session', 'client-1', None, None)

    query = _query(url)
    assert 'id_token_hint' not in query
    assert 'post_logout_redirect_uri' not in query
    assert query['client_id'] == ['client-1']
