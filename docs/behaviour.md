# Behaviour

A development CLI for the OAuth2/OIDC authorization code flow. It discovers
the provider config, opens the authorization URL in a browser, catches the
callback on a local HTTP server, and shows the tokens together with their
decoded JWT parts. It stays alive while the page is open, so the issued
tokens can be refreshed, introspected and revoked from it.

## Pages and flow

`/` is the UI the user logs in to. With tokens in hand it renders the result
page; without them it starts a fresh flow and redirects to the provider's
authorization URL.

The callback path is a protocol endpoint. On success it exchanges the code and
redirects to `/`, so the authorization code never lingers in the address bar or
in history. On failure it renders the error page, whose "try again" link points
back at `/` and therefore restarts the flow — without restarting the CLI. In
`--stdout` mode it renders the "you can close this tab" notice instead, since
there is no UI to hand off to.

A callback that fails the `state` check is rejected without consuming the
one-shot exchange guard, so a stray or forged redirect cannot block the
legitimate callback that follows.

## Result page

An identity card built from the id_token, or from the access_token when
that is a JWT too, heads the page and falls back to sub alone when no name
claims are present. Below it, one tab per token plus a userinfo tab, each
token collapsed to a single line with expand, copy and a live countdown to
expiry.

## Page actions

Refresh replaces the whole token set and reloads the page. Userinfo,
introspection and revocation only report on what exists and render in
place, next to the token they act on. Revocation asks for confirmation and
marks the token afterwards.

## Ending the session

Revocation kills tokens, not the login: the provider still recognises the
browser and hands out a new grant without a prompt. Ending the session
instead uses RP-initiated logout, opened in a new tab so the result page
keeps pinging and stays open. `--post-logout-redirect` is off by default
because providers reject the parameter unless it is registered.

## Output modes

By default nothing but the endpoints and the authorization URL reaches
stdout, and the browser is the interface. With `--stdout`, the callback
page only asks to be closed, and the whole result is dumped to the
terminal instead, each token raw on its own line.

That dump is meant to be piped, so it carries no ANSI escapes and no value is
ever wrapped or truncated. Colour appears only when stdout is a terminal and
`NO_COLOR` is unset.

## Logging

Errors only by default, which keeps the terminal silent — the page pings every
few seconds, so an access log would otherwise never stop scrolling. `-v` raises
it to warnings, `-vv` to info, `-vvv` to debug, and uvicorn obeys the same
level. Token values, the client secret, the code verifier and the authorization
code are never logged at any level; the authorization code is stripped out of
access log lines.

## Known wart

`--client-secret` is passed on the command line, so it lands in shell history
and is visible in `ps`. An environment variable fallback would fix it, but that
is a feature rather than a cleanup, and this is a local development tool.
