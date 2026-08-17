"""Decides what the result page shows, without producing any markup.

An identity card built from the id_token, or from the access_token when
that is a JWT too, heads the page and falls back to sub alone when no name
claims are present. Below it one tab per token, each carrying its own expiry,
decoded claims and available actions, then a tab for whatever else the token
response held, then a userinfo tab. Decoding is unverified base64url -- no key
material is fetched, so it is for inspection only, never for trust.
"""

import re
from dataclasses import dataclass

from oauthenticator.oauth2.identity import Identity
from oauthenticator.oauth2.jwt import Jwt
from oauthenticator.oauth2.tokens import TOKEN_NAMES, expires_at, issued_at

CURL_FALLBACK = 'https://api.example.com/resource'
INITIALS_LENGTH = 2
# Unicode-aware for str patterns, so a name in any script still splits into words.
NAME_SPLIT_PATTERN = re.compile(r'\W+')


@dataclass
class LifetimeView:
    """Both ends of a token's life, for the bar that draws how much of it is spent."""

    start: float
    start_label: str
    expires_at: float


@dataclass
class DecodedTokenView:
    header: dict
    payload: dict
    signature: str


@dataclass
class TokenPanelView:
    name: str
    value: str
    lifetime: LifetimeView | None
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
    initials: str
    email: str | None
    email_verified: bool
    facts: list


@dataclass
class SessionActionsView:
    can_refresh: bool
    end_session_url: str | None


@dataclass
class ErrorView:
    headline: str
    lines: list
    detail: str


@dataclass
class PathsView:
    """The route and static-asset paths the page references, owned by web/ and passed in as data."""

    root: str
    ping: str
    quit: str
    refresh: str
    userinfo: str
    introspect: str
    revoke: str
    css: str
    js: str


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
    css: str


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


def build_notice(session, css):
    message = ('The authorization failed, see the terminal.' if session.error is not None
               else 'The tokens are in the terminal.')

    return NoticeView(message=message, css=css)


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

    return ErrorView(headline=headline, lines=lines, detail=session.error)


def _identity_view(session):
    identity = Identity.from_tokens(session.tokens)
    initials = _initials(identity, session.tokens)
    if identity.source is None:
        return IdentityView(source=None, picture=None, name='Unknown user', initials=initials,
                            email=None, email_verified=False, facts=[])

    name = identity.name
    email = identity.email if identity.email != name else None
    facts = [(key, identity.claim(key)) for key in ('sub', 'iss')
             if identity.claim(key) is not None and identity.claim(key) != name]

    return IdentityView(
        source=identity.source, picture=identity.picture, name=name, initials=initials,
        email=email, email_verified=identity.email_verified, facts=facts)


def _initials(identity, tokens):
    """Two letters for the avatar tile, from the most specific claim that yields any.

    Walks real name claims down to the raw token text rather than giving up: an
    opaque pair of characters still identifies the tile, where a question mark
    says only that this failed. Identity.name is deliberately not consulted --
    it substitutes 'Unknown user' when no claim carries a name, which would put
    the initials of a placeholder on screen.
    """
    given = identity.claim('given_name')
    family = identity.claim('family_name')
    if given and family:
        return (given[0] + family[0]).upper()

    for key in Identity.NAME_CLAIMS:
        letters = _initials_of(identity.claim(key))
        if letters:
            return letters

    return _initials_of(_first_token(tokens))


def _initials_of(text):
    """Initials of the first two words, or the leading characters of a single word."""
    if not text:
        return ''

    local_part = text.split('@')[0]
    words = [word for word in NAME_SPLIT_PATTERN.split(local_part) if word]
    if len(words) >= INITIALS_LENGTH:
        return ''.join(word[0] for word in words[:INITIALS_LENGTH]).upper()

    return (words[0] if words else local_part)[:INITIALS_LENGTH].upper()


def _first_token(tokens):
    for name in TOKEN_NAMES:
        value = (tokens or {}).get(name)
        if isinstance(value, str) and value:
            return value

    return None


def _extras(tokens):
    """Whatever the token response carried besides the tokens themselves.

    Kept as the provider sent it, types intact, so the page can pretty-print it
    as JSON rather than as flattened text.
    """
    return {name: value for name, value in tokens.items()
            if not (name in TOKEN_NAMES and isinstance(value, str))}


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
        name=name, value=value, lifetime=_lifetime(session, name),
        is_id_token=is_id_token, can_curl=name == 'access_token', curl_command=curl_command,
        can_introspect=not is_id_token and session.client.supports('introspection_endpoint'),
        can_revoke=not is_id_token and session.client.supports('revocation_endpoint'),
        revoked=name in session.revoked, decoded=_decoded_token(value))


def _lifetime(session, name):
    """None when the token's expiry is unknowable -- there is no life to draw."""
    expiry = expires_at(session.tokens, name, session.received_at)
    start, start_label = issued_at(session.tokens, name, session.received_at)
    if expiry is None or start is None:
        return None

    return LifetimeView(start=start, start_label=start_label, expires_at=expiry)


def _decoded_token(value):
    decoded = Jwt.decode(value)
    if decoded is None:
        return None

    return DecodedTokenView(header=decoded['header'], payload=decoded['payload'],
                            signature=decoded['signature'])


def _userinfo_panel(session):
    return UserinfoPanelView(data=session.userinfo, error=session.userinfo_error)
