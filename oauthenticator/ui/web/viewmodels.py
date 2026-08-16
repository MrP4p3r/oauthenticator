"""Decides what the result page shows, without producing any markup.

An identity card built from the id_token, or from the access_token when
that is a JWT too, heads the page and falls back to sub alone when no name
claims are present. Below it one tab per token plus a userinfo tab, each
carrying its own expiry, decoded claims and available actions. Decoding is
unverified base64url -- no key material is fetched, so it is for inspection
only, never for trust.
"""

import json
from dataclasses import dataclass, field

from oauthenticator.oauth2.identity import Identity
from oauthenticator.oauth2.jwt import Jwt
from oauthenticator.oauth2.tokens import TIME_CLAIMS, TOKEN_NAMES, expires_at, is_number

CURL_FALLBACK = 'https://api.example.com/resource'


@dataclass
class TimeClaimView:
    claim: str
    value: float
    is_deadline: bool


@dataclass
class DecodedTokenView:
    header: dict
    payload: dict
    signature: str
    times: list = field(default_factory=list)


@dataclass
class TokenPanelView:
    name: str
    value: str
    expires_at: float | None
    is_id_token: bool
    can_curl: bool
    curl_command: str | None
    can_introspect: bool
    can_revoke: bool
    revoked: bool
    decoded: DecodedTokenView | None


@dataclass
class UserinfoPanelView:
    data: dict | None
    error: str | None


@dataclass
class IdentityView:
    source: str | None
    picture: str | None
    name: str
    email: str | None
    email_verified: bool
    facts: list
    expires_at: float | None


@dataclass
class SessionActionsView:
    can_refresh: bool
    end_session_url: str | None


@dataclass
class ErrorView:
    headline: str
    lines: list
    has_callback_params: bool
    detail: str


@dataclass
class PathsView:
    """The route paths the page's own script calls, owned by web/ and passed in as data."""

    root: str
    ping: str
    quit: str
    refresh: str
    userinfo: str
    introspect: str
    revoke: str


@dataclass
class ResultPageView:
    title: str
    action_token: str
    session_actions: SessionActionsView
    error: ErrorView | None
    identity: IdentityView | None
    extras: list
    tokens: list
    userinfo: UserinfoPanelView | None
    paths: PathsView


@dataclass
class NoticeView:
    message: str


def build_result_page(session, paths):
    if session.error is not None:
        return ResultPageView(
            title='Authorization failed', action_token=session.action_token,
            session_actions=_session_actions(session), error=_error_view(session),
            identity=None, extras=[], tokens=[], userinfo=None, paths=paths)

    return ResultPageView(
        title='Authorization complete', action_token=session.action_token,
        session_actions=_session_actions(session), error=None,
        identity=_identity_view(session), extras=_extras(session.tokens),
        tokens=_token_panels(session), userinfo=_userinfo_panel(session), paths=paths)


def build_notice(session):
    message = ('The authorization failed, see the terminal.' if session.error is not None
               else 'The tokens are in the terminal.')

    return NoticeView(message=message)


def _session_actions(session):
    can_refresh = isinstance((session.tokens or {}).get('refresh_token'), str)
    end_session_url = (session.end_session_url() if session.client.supports('end_session_endpoint')
                       else None)

    return SessionActionsView(can_refresh=can_refresh, end_session_url=end_session_url)


def _error_view(session):
    params = session.error_params
    headline = params.get('error') or 'The request never reached a token'
    lines = [params.get('error_description') or
             'nothing was issued, so there is nothing to inspect']

    if 'error_uri' in params:
        lines.append('error_uri ' + params['error_uri'])

    return ErrorView(headline=headline, lines=lines, has_callback_params=bool(params),
                     detail=session.error)


def _identity_view(session):
    identity = Identity.from_tokens(session.tokens)
    if identity.source is None:
        return IdentityView(source=None, picture=None, name='Unknown user', email=None,
                            email_verified=False, facts=[], expires_at=None)

    name = identity.name
    email = identity.email if identity.email != name else None
    facts = [(key, identity.claim(key)) for key in ('sub', 'iss')
             if identity.claim(key) is not None and identity.claim(key) != name]

    return IdentityView(
        source=identity.source, picture=identity.picture, name=name, email=email,
        email_verified=identity.email_verified, facts=facts, expires_at=identity.expires_at)


def _extras(tokens):
    extras = []

    for name, value in tokens.items():
        if name in TOKEN_NAMES and isinstance(value, str):
            continue

        extras.append((name, value if isinstance(value, str) else json.dumps(value)))

    return extras


def _token_panels(session):
    names = [name for name in TOKEN_NAMES if isinstance(session.tokens.get(name), str)]

    return [_token_panel(session, name) for name in names]


def _token_panel(session, name):
    value = session.tokens[name]
    is_id_token = name == 'id_token'

    curl_command = None
    if name == 'access_token':
        endpoint = session.client.config.get('userinfo_endpoint') or CURL_FALLBACK
        curl_command = f'curl -H "Authorization: Bearer {value}" "{endpoint}"'

    return TokenPanelView(
        name=name, value=value, expires_at=expires_at(session.tokens, name, session.received_at),
        is_id_token=is_id_token, can_curl=name == 'access_token', curl_command=curl_command,
        can_introspect=not is_id_token and session.client.supports('introspection_endpoint'),
        can_revoke=not is_id_token and session.client.supports('revocation_endpoint'),
        revoked=name in session.revoked, decoded=_decoded_token(value))


def _decoded_token(value):
    decoded = Jwt.decode(value)
    if decoded is None:
        return None

    times = [TimeClaimView(claim=claim, value=decoded['payload'][claim], is_deadline=claim == 'exp')
             for claim in TIME_CLAIMS if is_number(decoded['payload'].get(claim))]

    return DecodedTokenView(header=decoded['header'], payload=decoded['payload'],
                            signature=decoded['signature'], times=times)


def _userinfo_panel(session):
    return UserinfoPanelView(data=session.userinfo, error=session.userinfo_error)
