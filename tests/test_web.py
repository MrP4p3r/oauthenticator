"""The HTTP surface, driven through httpx.ASGITransport against the real app.

`running_app` builds the same objects __main__.py would at startup -- an
OidcClient over the fake provider, an AuthSession, and the FastAPI app from
create_app() -- and hands back a client for it, also reached only through
ASGITransport, so nothing here touches a socket.
"""

import contextlib

import httpx

from oauthenticator.oauth2.client import OidcClient
from oauthenticator.state.session import AuthSession
from oauthenticator.web.app import create_app
from tests.plugins.oidc_provider.app import CLIENT_ID, CLIENT_SECRET, build_http_client

REDIRECT_URI = 'http://localhost:8765/callback'
CALLBACK_PATH = '/callback'
SCOPE = 'openid email profile'


class RunningApp:
    """The web app under test, its session, and a client for the provider behind it."""

    def __init__(self, app_client, session, provider_http):
        self.app_client = app_client
        self.session = session
        self.provider_http = provider_http

    async def authorize_and_call_back(self):
        """Drives the real front channel: GET the authorization URL, then follow its
        redirect into the app's callback -- no shortcuts through the state machine.
        """
        authorization_url = httpx.URL(self.session.authorization_url())
        authorize_response = await self.provider_http.get(
            authorization_url.path, params=authorization_url.params, follow_redirects=False)
        callback_location = httpx.URL(authorize_response.headers['location'])

        return await self.app_client.get(
            CALLBACK_PATH, params=callback_location.params, follow_redirects=False)


@contextlib.asynccontextmanager
async def running_app(provider, *, stdout_mode=False, client_id=CLIENT_ID,
                      client_secret=CLIENT_SECRET, idle_timeout=120.0):
    async with build_http_client(provider) as provider_http:
        oidc_client = OidcClient(provider_http, provider.issuer, client_id, client_secret)
        await oidc_client.discover()

        session = AuthSession(oidc_client, REDIRECT_URI, SCOPE, idle_timeout, None)
        app = create_app(session, CALLBACK_PATH, stdout_mode)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://testserver') as app_client:
            yield RunningApp(app_client, session, provider_http)


async def test_root_redirects_to_the_authorization_endpoint_without_tokens(oidc_provider):
    async with running_app(oidc_provider) as running:
        response = await running.app_client.get('/', follow_redirects=False)

        assert response.status_code == 302
        assert response.headers['location'].startswith(f'{oidc_provider.issuer}/authorize?')


async def test_root_restarts_the_flow_on_every_visit_without_tokens(oidc_provider):
    async with running_app(oidc_provider) as running:
        first = await running.app_client.get('/', follow_redirects=False)
        second = await running.app_client.get('/', follow_redirects=False)

        assert first.headers['location'] != second.headers['location']


async def test_full_flow_authorization_to_rendered_page(oidc_provider):
    async with running_app(oidc_provider) as running:
        callback_response = await running.authorize_and_call_back()

        assert callback_response.status_code == 303
        assert callback_response.headers['location'] == '/'
        assert running.session.tokens is not None
        assert running.session.error is None

        page_response = await running.app_client.get('/')

        assert page_response.status_code == 200
        assert 'Authorization complete' in page_response.text
        assert running.session.tokens['access_token'] in page_response.text


async def test_rendering_escapes_claim_values(oidc_provider):
    oidc_provider.identity_claims['name'] = '<script>alert(1)</script>'
    oidc_provider.identity_claims['email'] = 'a"b@example.com'

    async with running_app(oidc_provider) as running:
        await running.authorize_and_call_back()
        page_response = await running.app_client.get('/')

        assert '<script>alert(1)</script>' not in page_response.text
        assert '&lt;script&gt;alert(1)&lt;/script&gt;' in page_response.text
        assert 'a"b@example.com' not in page_response.text


async def test_rendering_json_escapes_claim_values_as_json(oidc_provider):
    """A claim carrying JSON metacharacters must not break the pretty-printed block.

    Rendered as a bare "{{ value }}" a quote would close the string early and a
    raw newline would split the <pre> layout, so the claims panel would show
    malformed JSON for a token the provider considers perfectly valid.
    """
    oidc_provider.identity_claims['broken'] = 'quote:" backslash:\\ newline:\n tag:<b>'

    async with running_app(oidc_provider) as running:
        await running.authorize_and_call_back()
        page_response = await running.app_client.get('/')
        claims_block = page_response.text.split('json-string')[1]

        assert '"quote:\\" backslash:\\\\ newline:\\n' in page_response.text
        assert 'newline:\n' not in claims_block
        assert '<b>' not in claims_block


async def test_callback_failure_renders_an_error_page_with_a_retry_link(oidc_provider):
    oidc_provider.fail_authorization = {'error': 'access_denied',
                                        'error_description': 'the user said no'}

    async with running_app(oidc_provider) as running:
        response = await running.authorize_and_call_back()

        assert response.status_code == 200
        assert 'access_denied' in response.text
        assert 'href="/"' in response.text
        assert running.session.tokens is None


async def test_callback_in_stdout_mode_renders_the_notice_card(oidc_provider):
    async with running_app(oidc_provider, stdout_mode=True) as running:
        response = await running.authorize_and_call_back()

        assert response.status_code == 200
        assert 'close this tab' in response.text
        assert running.session.delivered.is_set()


async def test_ping_keeps_the_session_from_going_idle(oidc_provider):
    async with running_app(oidc_provider, idle_timeout=0.01) as running:
        response = await running.app_client.get('/ping')

        assert response.status_code == 200
        assert response.text == 'ok'
        assert running.session.is_idle() is False


async def test_action_endpoint_rejects_a_wrong_action_token(oidc_provider):
    async with running_app(oidc_provider) as running:
        await running.authorize_and_call_back()

        response = await running.app_client.post('/api/refresh', json={'action_token': 'wrong'})

        assert response.status_code == 403
        assert response.json() == {'error': 'bad action token'}


async def test_introspect_and_revoke_act_on_the_token_named_in_the_path(oidc_provider):
    async with running_app(oidc_provider) as running:
        await running.authorize_and_call_back()
        action_token = running.session.action_token

        introspect_response = await running.app_client.post(
            '/api/introspect/access_token', json={'action_token': action_token})
        assert introspect_response.status_code == 200
        assert oidc_provider.captured_token_request['token_type_hint'] == 'access_token'

        revoke_response = await running.app_client.post(
            '/api/revoke/refresh_token', json={'action_token': action_token})
        assert revoke_response.status_code == 200
        assert oidc_provider.captured_token_request['token_type_hint'] == 'refresh_token'
        assert 'refresh_token' in running.session.revoked


async def test_refresh_replaces_the_token_set(oidc_provider):
    async with running_app(oidc_provider) as running:
        await running.authorize_and_call_back()
        refresh_token_before = running.session.tokens['refresh_token']

        response = await running.app_client.post(
            '/api/refresh', json={'action_token': running.session.action_token})

        assert response.status_code == 200
        assert oidc_provider.captured_token_request['grant_type'] == 'refresh_token'
        assert oidc_provider.captured_token_request['refresh_token'] == refresh_token_before
        # the fake provider mints a fresh (random) refresh_token on every grant,
        # so a real replacement -- not a no-op -- shows up here unambiguously
        assert running.session.tokens['refresh_token'] != refresh_token_before


async def test_userinfo_endpoint_refetches_userinfo(oidc_provider):
    async with running_app(oidc_provider) as running:
        await running.authorize_and_call_back()

        response = await running.app_client.post(
            '/api/userinfo', json={'action_token': running.session.action_token})

        assert response.status_code == 200
        assert response.json()['sub'] == oidc_provider.identity_claims['sub']


async def test_quit_sets_the_finished_event(oidc_provider):
    async with running_app(oidc_provider) as running:
        response = await running.app_client.post(
            '/api/quit', json={'action_token': running.session.action_token})

        assert response.status_code == 200
        assert running.session.finished.is_set()


async def test_page_renders_with_only_an_access_token(oidc_provider):
    async with running_app(oidc_provider) as running:
        await running.authorize_and_call_back()
        running.session.tokens = {'access_token': running.session.tokens['access_token']}

        response = await running.app_client.get('/')

        assert response.status_code == 200
        assert 'data-tab="access_token"' in response.text
        assert 'data-tab="id_token"' not in response.text
        assert 'data-tab="refresh_token"' not in response.text


async def test_page_renders_with_a_full_token_set(oidc_provider):
    async with running_app(oidc_provider) as running:
        await running.authorize_and_call_back()

        response = await running.app_client.get('/')

        assert response.status_code == 200
        for name in ('access_token', 'id_token', 'refresh_token'):
            assert f'data-tab="{name}"' in response.text


async def test_page_renders_when_the_provider_advertises_no_optional_endpoints(provider_factory):
    provider = provider_factory(include_userinfo=False, include_introspection=False,
                                include_revocation=False, include_end_session=False)

    async with running_app(provider) as running:
        await running.authorize_and_call_back()
        response = await running.app_client.get('/')

        assert response.status_code == 200
        assert 'Introspect</button>' not in response.text
        assert 'Revoke</button>' not in response.text
        assert 'End provider session' not in response.text
        assert 'not fetched yet' in response.text or 'userinfo_endpoint' in response.text
