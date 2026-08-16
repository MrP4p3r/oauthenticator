"""Turns result-page view models into HTML strings."""

import html
import json
import time

from oauthenticator.oauth2.tokens import TIME_FORMAT
from oauthenticator.ui.web import templates


def render(view):
    body = _render_error(view.error) if view.error is not None else _render_result(view)

    return templates.RESULT_PAGE.substitute(
        title=view.title, body=body, action_token=view.action_token,
        session_actions=_render_session_actions(view.session_actions),
        ping_path=templates.PING_PATH, ping_interval=templates.PING_INTERVAL,
        finish_path=templates.FINISH_PATH, refresh_path=templates.REFRESH_PATH,
        userinfo_path=templates.USERINFO_PATH, introspect_path=templates.INTROSPECT_PATH,
        revoke_path=templates.REVOKE_PATH).encode()


def render_notice(view):
    return templates.NOTICE.substitute(message=view.message).encode()


def _render_session_actions(actions):
    buttons = []

    if actions.can_refresh:
        buttons.append('<button onclick="refreshTokens(this)">Refresh the token set</button>')

    if actions.end_session_url is not None:
        url = html.escape(actions.end_session_url)
        buttons.append(f'<button class="danger" data-url="{url}" onclick="endSession(this)">'
                       'End provider session</button>')

    return ''.join(buttons)


def _render_error(error):
    chunks = ['<div class="identity"><div class="who">',
              f'<div class="name failed">{html.escape(error.headline)}</div>']
    chunks.extend(f'<div class="line">{html.escape(line)}</div>' for line in error.lines)
    chunks.append('</div>')

    if error.has_callback_params:
        chunks.append('<span class="badge">callback</span>')

    chunks.append('</div>')

    return ''.join(chunks) + f'\n<pre class="result failed">{html.escape(error.detail)}</pre>'


def _render_result(view):
    return '\n'.join([
        _render_identity(view.identity),
        _render_extras(view.extras),
        _render_tabs(view),
    ])


def _render_identity(identity):
    if identity.source is None:
        return ('<div class="identity"><div class="who">'
                '<div class="name">Unknown user</div>'
                '<div class="line">the response carries no JWT to decode</div>'
                '</div></div>')

    chunks = ['<div class="identity">']
    if identity.picture is not None:
        chunks.append(f'<img src="{html.escape(identity.picture)}" alt="" '
                      'referrerpolicy="no-referrer" onerror="this.remove()">')

    chunks.append('<div class="who">')
    chunks.append(f'<div class="name">{html.escape(identity.name)}</div>')
    chunks.extend(f'<div class="line">{line}</div>' for line in _identity_lines(identity))
    chunks.append('</div>')
    chunks.append(f'<span class="badge">{identity.source}</span>')
    chunks.append('</div>')

    return ''.join(chunks)


def _identity_lines(identity):
    lines = []

    if identity.email is not None:
        verified = ' ✓ verified' if identity.email_verified else ''
        lines.append(html.escape(identity.email) + verified)

    if identity.facts:
        facts = [f'{key} <span class="mono">{html.escape(value)}</span>'
                 for key, value in identity.facts]
        lines.append(' &middot; '.join(facts))

    expiry = _render_expiry(identity.expires_at)
    if expiry is not None:
        lines.append(expiry)

    return lines


def _render_expiry(expires_at):
    if expires_at is None:
        return None

    stamp = time.strftime(TIME_FORMAT, time.gmtime(expires_at))

    return f'expires {stamp} &middot; <span data-time="{expires_at:.0f}" data-deadline></span>'


def _render_extras(extras):
    if not extras:
        return ''

    chips = [f'<span class="chip"><b>{html.escape(name)}</b> {html.escape(text)}</span>'
             for name, text in extras]

    return '<div class="meta">' + ''.join(chips) + '</div>'


def _render_tabs(view):
    items = [(panel.name, panel.revoked, _render_token(panel)) for panel in view.tokens]
    items.append(('userinfo', False, _render_userinfo(view.userinfo)))

    buttons = []
    sections = []
    for index, (name, revoked, content) in enumerate(items):
        classes = ['panel']
        if index == 0:
            classes.append('active')
        if revoked:
            classes.append('revoked')

        active = ' class="active"' if index == 0 else ''
        buttons.append(f'<button{active} data-tab="{name}" '
                       f'onclick="selectTab(\'{name}\')">{name}</button>')
        sections.append(f'<section class="{" ".join(classes)}" data-tab="{name}">'
                        + content + '</section>')

    return '<nav class="tabs">' + ''.join(buttons) + '</nav>\n' + '\n'.join(sections)


def _render_token(panel):
    chunks = [
        '<div class="token">'
        '<button title="Expand" onclick="toggleToken(this)">▸</button>'
        f'<code class="value">{html.escape(panel.value)}</code>'
        '<button title="Copy" onclick="copyValue(this)">📋</button>'
        '</div>'
    ]

    expiry = _render_expiry(panel.expires_at)
    if expiry is not None:
        chunks.append(f'<p class="note">{expiry}</p>')

    chunks.append(_render_actions(panel))
    chunks.append('<pre class="result" hidden></pre>')
    chunks.extend(_render_claims(panel))

    return '\n'.join(chunks)


def _render_actions(panel):
    if panel.is_id_token:
        return ('<p class="note">An id_token is not an OAuth token: introspection and '
                'revocation do not apply to it.</p>')

    buttons = []
    if panel.can_curl:
        buttons.append(f'<button data-curl="{html.escape(panel.curl_command)}" '
                       'onclick="copyCurl(this)">Copy as curl</button>')

    if panel.can_introspect:
        buttons.append(f'<button onclick="introspect(\'{panel.name}\')">Introspect</button>')

    if panel.can_revoke:
        buttons.append(f'<button class="danger" onclick="revoke(\'{panel.name}\')">Revoke</button>')

    if not buttons:
        return ''

    return '<div class="actions">' + ''.join(buttons) + '</div>'


def _render_userinfo(userinfo):
    if userinfo.data is not None:
        text = json.dumps(userinfo.data, indent=2)
        failed = ''
    else:
        text = userinfo.error or 'not fetched yet'
        failed = ' failed'

    return ('<div class="actions">'
            '<button onclick="reloadUserinfo()">Fetch again</button>'
            '</div>\n'
            f'<pre class="result{failed}">{html.escape(text)}</pre>')


def _render_claims(panel):
    if panel.decoded is None:
        return ['<p class="note">Not a JWT, nothing to decode.</p>']

    header = html.escape(json.dumps(panel.decoded.header, indent=2))
    payload = html.escape(json.dumps(panel.decoded.payload, indent=2))
    signature = html.escape(panel.decoded.signature)

    return [
        f'<h3>header</h3><pre>{header}</pre>',
        f'<h3>payload</h3><pre>{payload}</pre>',
        _render_times(panel.decoded.times),
        f'<h3>signature</h3><pre>{signature}</pre>',
    ]


def _render_times(times):
    if not times:
        return ''

    lines = []
    for time_claim in times:
        stamp = time.strftime(TIME_FORMAT, time.gmtime(time_claim.value))
        deadline = ' data-deadline' if time_claim.is_deadline else ''
        lines.append(f'<div class="line"><b>{time_claim.claim}</b> {stamp} &middot; '
                     f'<span data-time="{time_claim.value:.0f}"{deadline}></span></div>')

    return '<div class="times">' + ''.join(lines) + '</div>'
