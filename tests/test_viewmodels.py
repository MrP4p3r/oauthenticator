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
    # not 'UU' -- 'Unknown user' is a placeholder, so the tile reads the token instead
    assert view.initials == 'OA'


def test_initials_prefer_the_given_and_family_name_claims(token_signer):
    id_token = token_signer.sign({'sub': 'user-1', 'name': 'ignored entirely',
                                  'given_name': 'Ada', 'family_name': 'Lovelace'})
    session = FakeSession(tokens={'id_token': id_token})

    assert viewmodels._identity_view(session).initials == 'AL'


def test_initials_survive_a_name_in_a_non_latin_script(token_signer):
    """A Cyrillic name used to split into zero words and render as a question mark."""
    id_token = token_signer.sign({'sub': 'user-1', 'name': 'Глеб Гетманенко'})
    session = FakeSession(tokens={'id_token': id_token})

    assert viewmodels._identity_view(session).initials == 'ГГ'


def test_initials_take_the_local_part_of_an_email_shaped_username(token_signer):
    id_token = token_signer.sign({'sub': 'user-1', 'preferred_username': 'gleb@example.com'})
    session = FakeSession(tokens={'id_token': id_token})

    assert viewmodels._identity_view(session).initials == 'GL'


def test_initials_fall_back_to_the_sub_claim_when_no_name_claim_exists(token_signer):
    id_token = token_signer.sign({'sub': 'ff01dead'})
    session = FakeSession(tokens={'id_token': id_token})

    assert viewmodels._identity_view(session).initials == 'FF'


def test_initials_never_render_a_question_mark(token_signer):
    """Every rung of the ladder yields letters, so the placeholder is unreachable."""
    cases = [
        {'id_token': token_signer.sign({'name': 'Ada'})},
        {'id_token': token_signer.sign({'name': '!!! ???'})},
        {'access_token': 'opaque-at'},
    ]

    for tokens in cases:
        assert viewmodels._identity_view(FakeSession(tokens=tokens)).initials != '?'


def test_extras_keeps_only_non_standard_or_non_string_token_fields(token_signer):
    tokens = {
        'access_token': token_signer.sign({'sub': 'user-1'}),
        'token_type': 'Bearer',
        'scope': 'openid email',
        'extra_metadata': {'nested': True},
    }

    extras = viewmodels._extras(tokens)

    assert 'access_token' not in extras
    assert extras['token_type'] == 'Bearer'
    # kept as the provider sent it, so the page can pretty-print it as JSON
    assert extras['extra_metadata'] == {'nested': True}


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


def test_lifetime_reads_both_ends_from_the_jwt_claims(token_signer):
    token = token_signer.sign({'sub': 'user-1', 'iat': 1000, 'exp': 2000})
    session = FakeSession(tokens={'access_token': token})

    lifetime = viewmodels._token_panel(session, 'access_token').lifetime

    assert (lifetime.start, lifetime.start_label, lifetime.expires_at) == (1000, 'iat', 2000)


def test_lifetime_falls_back_to_nbf_when_a_token_carries_no_iat(token_signer):
    token = token_signer.sign({'sub': 'user-1', 'nbf': 1500, 'exp': 2000})
    session = FakeSession(tokens={'access_token': token})

    lifetime = viewmodels._token_panel(session, 'access_token').lifetime

    assert (lifetime.start, lifetime.start_label) == (1500, 'nbf')


def test_lifetime_of_an_opaque_token_runs_from_when_it_was_received():
    """No claims to read, but expires_in plus the arrival time still bound its life."""
    session = FakeSession(tokens={'refresh_token': 'opaque-rt', 'refresh_expires_in': 600},
                          received_at=1000)

    lifetime = viewmodels._token_panel(session, 'refresh_token').lifetime

    assert (lifetime.start, lifetime.start_label, lifetime.expires_at) == (1000, 'recv', 1600)


def test_no_lifetime_when_nothing_bounds_the_token():
    session = FakeSession(tokens={'refresh_token': 'opaque-rt'}, received_at=1000)

    assert viewmodels._token_panel(session, 'refresh_token').lifetime is None


def test_build_notice_reports_a_terminal_message_and_reflects_the_error_state():
    css = '/static/app.css'

    assert 'terminal' in viewmodels.build_notice(FakeSession(error='boom'), css).message
    assert 'terminal' in viewmodels.build_notice(FakeSession(tokens={}), css).message
