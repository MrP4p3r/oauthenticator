"""ui/web/viewmodels.py -- what the result page shows, decided from an AuthSession.

A minimal stand-in session is enough here; the templates render the view
models it produces, tested separately in tests/test_web.py.
"""

from oauthenticator.ui.web import viewmodels


class FakeClient:
    def __init__(self, config=None):
        self.config = config or {}

    def supports(self, endpoint):
        return endpoint in self.config

    def end_session_url(self, id_token, post_logout_redirect):
        return 'https://issuer.test/end_session?id_token_hint=' + (id_token or '')


class FakeSession:
    def __init__(self, *, tokens=None, error=None, error_params=None, received_at=None,
                userinfo=None, userinfo_error=None, revoked=None, config=None,
                action_token='action-token-1'):
        self.client = FakeClient(config)
        self.tokens = tokens
        self.error = error
        self.error_params = error_params or {}
        self.received_at = received_at
        self.userinfo = userinfo
        self.userinfo_error = userinfo_error
        self.revoked = revoked or set()
        self.action_token = action_token

    def end_session_url(self):
        id_token = (self.tokens or {}).get('id_token')

        return self.client.end_session_url(id_token, post_logout_redirect=None)


def test_build_result_page_shows_the_error_view_when_the_session_has_an_error():
    session = FakeSession(error='access_denied: nope',
                          error_params={'error': 'access_denied', 'error_description': 'nope'})

    view = viewmodels.build_result_page(session, paths=object())

    assert view.title == 'Authorization failed'
    assert view.error.headline == 'access_denied'
    assert view.tokens == []
    assert view.identity is None


def test_build_result_page_shows_tokens_and_identity_on_success(token_signer):
    id_token = token_signer.sign({'sub': 'user-1', 'name': 'Ada'})
    session = FakeSession(tokens={'id_token': id_token, 'access_token': 'opaque-at'})

    view = viewmodels.build_result_page(session, paths=object())

    assert view.title == 'Authorization complete'
    assert view.error is None
    assert view.identity.name == 'Ada'
    assert [panel.name for panel in view.tokens] == ['access_token', 'id_token']


def test_session_actions_offers_refresh_only_when_a_refresh_token_exists():
    with_refresh = FakeSession(tokens={'access_token': 'at', 'refresh_token': 'rt'})
    without_refresh = FakeSession(tokens={'access_token': 'at'})

    assert viewmodels._session_actions(with_refresh).can_refresh is True
    assert viewmodels._session_actions(without_refresh).can_refresh is False


def test_session_actions_offers_end_session_only_when_the_provider_advertises_it():
    with_end_session = FakeSession(tokens={}, config={'end_session_endpoint': 'x'})
    without_end_session = FakeSession(tokens={}, config={})

    assert viewmodels._session_actions(with_end_session).end_session_url is not None
    assert viewmodels._session_actions(without_end_session).end_session_url is None


def test_identity_view_falls_back_to_unknown_user_without_a_jwt():
    session = FakeSession(tokens={'access_token': 'opaque-at'})

    view = viewmodels._identity_view(session)

    assert view.source is None
    assert view.name == 'Unknown user'
    assert view.facts == []


def test_extras_keeps_only_non_standard_or_non_string_token_fields(token_signer):
    tokens = {
        'access_token': token_signer.sign({'sub': 'user-1'}),
        'token_type': 'Bearer',
        'scope': 'openid email',
        'extra_metadata': {'nested': True},
    }

    extras = viewmodels._extras(tokens)

    names = dict(extras)
    assert 'access_token' not in names
    assert names['token_type'] == 'Bearer'
    assert names['extra_metadata'] == '{"nested": true}'


def test_token_panels_include_only_tokens_present_as_strings():
    session = FakeSession(tokens={'access_token': 'at', 'id_token': None, 'refresh_token': 'rt'})

    panels = viewmodels._token_panels(session)

    assert [panel.name for panel in panels] == ['access_token', 'refresh_token']


def test_token_panel_curl_command_uses_the_userinfo_endpoint_when_advertised():
    session = FakeSession(tokens={'access_token': 'at'},
                          config={'userinfo_endpoint': 'https://issuer.test/userinfo'})

    panel = viewmodels._token_panel(session, 'access_token')

    assert 'https://issuer.test/userinfo' in panel.curl_command


def test_token_panel_curl_command_falls_back_when_userinfo_is_not_advertised():
    session = FakeSession(tokens={'access_token': 'at'})

    panel = viewmodels._token_panel(session, 'access_token')

    assert viewmodels.CURL_FALLBACK in panel.curl_command


def test_token_panel_actions_reflect_provider_capabilities():
    session = FakeSession(tokens={'access_token': 'at'},
                          config={'introspection_endpoint': 'x', 'revocation_endpoint': 'y'})

    panel = viewmodels._token_panel(session, 'access_token')

    assert panel.can_introspect is True
    assert panel.can_revoke is True


def test_id_token_never_offers_introspection_or_revocation(token_signer):
    id_token = token_signer.sign({'sub': 'user-1'})
    session = FakeSession(tokens={'id_token': id_token},
                          config={'introspection_endpoint': 'x', 'revocation_endpoint': 'y'})

    panel = viewmodels._token_panel(session, 'id_token')

    assert panel.can_introspect is False
    assert panel.can_revoke is False


def test_token_panel_decoded_is_none_for_an_opaque_token():
    session = FakeSession(tokens={'refresh_token': 'opaque-refresh'})

    panel = viewmodels._token_panel(session, 'refresh_token')

    assert panel.decoded is None


def test_token_panel_decoded_times_flag_exp_as_the_deadline(token_signer):
    token = token_signer.sign({'sub': 'user-1', 'iat': 1000, 'exp': 2000})
    session = FakeSession(tokens={'access_token': token})

    panel = viewmodels._token_panel(session, 'access_token')

    by_claim = {time_claim.claim: time_claim.is_deadline for time_claim in panel.decoded.times}
    assert by_claim == {'iat': False, 'exp': True}


def test_build_notice_reports_a_terminal_message_and_reflects_the_error_state():
    css = '/static/app.css'

    assert 'terminal' in viewmodels.build_notice(FakeSession(error='boom'), css).message
    assert 'terminal' in viewmodels.build_notice(FakeSession(tokens={}), css).message
