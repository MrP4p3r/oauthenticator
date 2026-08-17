"""state/session.py -- the flow state machine: the once-only guard, restart, idle detection.

A lightweight fake OidcClient stands in for the real one here, so these
tests are about state transitions, not HTTP -- the full callback -> exchange
-> render path against a real provider is covered in tests/test_web.py.
"""

import pytest

from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.state.session import AuthSession


class FakeClient:
    """Records calls and lets a test script the outcome of each one."""

    def __init__(self):
        self.exchange_calls = []
        self.refresh_calls = []
        self.userinfo_calls = []
        self.exchange_result = {'access_token': 'at-1', 'id_token': 'it-1', 'refresh_token': 'rt-1'}
        self.exchange_error = None
        self.userinfo_result = {'sub': 'user-1'}
        self.userinfo_error = None
        self.end_session_endpoint_supported = True
        self.introspect_calls = []
        self.revoke_calls = []

    async def exchange_code(self, code, redirect_uri, code_verifier):
        self.exchange_calls.append((code, redirect_uri, code_verifier))
        if self.exchange_error is not None:
            raise self.exchange_error

        return self.exchange_result

    async def refresh(self, refresh_token):
        self.refresh_calls.append(refresh_token)

        return self.exchange_result

    async def userinfo(self, access_token):
        self.userinfo_calls.append(access_token)
        if self.userinfo_error is not None:
            raise self.userinfo_error

        return self.userinfo_result

    async def introspect(self, token, hint):
        self.introspect_calls.append((token, hint))

        return {'active': True}

    async def revoke(self, token, hint):
        self.revoke_calls.append((token, hint))

        return {}

    def authorization_url(self, redirect_uri, scope, state, nonce, code_challenge):
        return f'https://issuer.test/authorize?state={state}'

    def end_session_url(self, id_token, post_logout_redirect):
        return 'https://issuer.test/end_session'

    def supports(self, endpoint):
        return self.end_session_endpoint_supported


@pytest.fixture
def client():
    return FakeClient()


@pytest.fixture
def session(client):
    return AuthSession(client, 'http://localhost:8765/callback', 'openid email',
                       idle_timeout=120.0, post_logout_redirect=None)


def success_query(session, extra=None):
    return {'state': [session.state], 'code': ['auth-code'], **(extra or {})}


def error_query(session, error='access_denied', state=None):
    query = {'error': [error], 'error_description': ['the user said no']}
    if state is not None:
        query['state'] = [state]

    return query


async def test_a_successful_callback_exchanges_once(session, client):
    accepted = await session.complete(success_query(session))

    assert accepted is True
    assert session.tokens == client.exchange_result
    assert len(client.exchange_calls) == 1


async def test_a_reload_does_not_re_exchange(session, client):
    await session.complete(success_query(session))
    accepted_again = await session.complete(success_query(session))

    assert accepted_again is False
    assert len(client.exchange_calls) == 1


async def test_a_forged_callback_does_not_consume_the_guard_before_the_legitimate_one(
        session, client):
    forged = await session.complete(success_query(session, extra={'state': ['not-the-state']}))
    legitimate = await session.complete(success_query(session))

    assert forged is False
    assert legitimate is True
    assert len(client.exchange_calls) == 1
    assert session.tokens == client.exchange_result


async def test_a_forged_error_callback_does_not_consume_the_guard_either(session):
    forged = await session.complete(error_query(session, state='not-the-state'))
    legitimate = await session.complete(success_query(session))

    assert forged is False
    assert legitimate is True
    assert session.tokens is not None


async def test_an_error_callback_with_no_state_at_all_is_still_accepted(session):
    accepted = await session.complete(error_query(session, state=None))

    assert accepted is True
    assert session.error == 'access_denied: the user said no'


async def test_an_error_callback_with_the_matching_state_is_accepted(session):
    accepted = await session.complete(error_query(session, state=session.state))

    assert accepted is True
    assert session.error == 'access_denied: the user said no'


async def test_a_callback_with_no_code_is_accepted_but_leaves_no_tokens(session):
    query = {'state': [session.state]}

    accepted = await session.complete(query)

    assert accepted is True
    assert session.tokens is None
    assert session.error == 'no code in the callback query'


async def test_a_failed_exchange_is_accepted_and_records_the_error(session, client):
    client.exchange_error = OAuth2Error('invalid_grant: bad code')

    accepted = await session.complete(success_query(session))

    assert accepted is True
    assert session.tokens is None
    assert session.error == 'invalid_grant: bad code'


async def test_restart_regenerates_flow_secrets_and_unlatches_the_guard(session, client):
    await session.complete(success_query(session))
    old_state = session.state

    session.restart()

    assert session.state != old_state
    assert session.error is None

    # a callback for the flow restart() just superseded must fail the state
    # check rather than resurrecting it
    stale = await session.complete({'state': [old_state], 'code': ['auth-code']})
    assert stale is False
    assert len(client.exchange_calls) == 1

    fresh = await session.complete(success_query(session))
    assert fresh is True
    assert len(client.exchange_calls) == 2


async def test_refresh_merges_the_new_tokens_over_the_old_set(session, client):
    await session.complete(success_query(session))
    client.exchange_result = {'access_token': 'at-2'}

    await session.refresh()

    assert session.tokens['access_token'] == 'at-2'
    assert session.tokens['id_token'] == 'it-1'


async def test_load_userinfo_records_the_error_without_raising(session, client):
    await session.complete(success_query(session))
    client.userinfo_error = OAuth2Error('userinfo failed')

    await session.load_userinfo()

    assert session.userinfo is None
    assert session.userinfo_error == 'userinfo failed'


async def test_revoke_marks_the_token_revoked(session, client):
    await session.complete(success_query(session))

    await session.revoke('access_token')

    assert 'access_token' in session.revoked


async def test_token_value_raises_for_a_token_the_session_does_not_have(session, client):
    client.exchange_result = {'access_token': 'at-1'}
    await session.complete(success_query(session))

    with pytest.raises(RuntimeError, match='refresh_token'):
        session.token_value('refresh_token')


async def test_is_idle_is_false_before_the_first_ping(session):
    assert session.is_idle() is False


async def test_is_idle_reflects_the_idle_timeout(session, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr('oauthenticator.state.session.time.monotonic', lambda: clock[0])
    session.idle_timeout = 10

    session.ping()
    assert session.is_idle() is False

    clock[0] += 11
    assert session.is_idle() is True
