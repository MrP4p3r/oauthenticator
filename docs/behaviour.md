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
claims are present. Below it, one tab per token, then an extras tab for
whatever else the token response carried, then a userinfo tab. The first
tab that exists is the selected one, and the selection is kept in the URL
hash, so a reload lands where it left off. Each token is collapsed to a
single line with expand and copy, and its decoded parts sit underneath.

Under the token value sits a lifetime bar, drawn only when the expiry is
knowable at all. Both ends are absolute UTC and therefore never jitter: the
start comes from iat or nbf, or from the moment the token set arrived when
the token carries no claims, labelled so the provider's assertion and our
own observation are told apart. The fill advances between the two, crossing
into a warning zone at 70% of the life and a critical one at 90%. The
relative form — how long until expiry, or how long ago — lives in the hover
tooltip on either end, where it is free to change width.

## Page actions

Refresh sits in the top bar rather than in a token tab, since it acts on
the whole set: it merges what the provider reissues over what is held, so a
token that is not reissued survives, clears the revoked marks and reloads
the page. Introspection and revocation only report on what exists and
render in place, in the tab of the token they act on; revocation asks for
confirmation and strikes the token through afterwards. Userinfo is fetched
again from its own tab. The access_token tab also hands out its value as a
ready curl command, aimed at the userinfo endpoint when the provider
advertises one and at a placeholder URL when it does not.

Quit stops the CLI from the page. The page keeps pinging either way, so
however the CLI ends — quit, idle timeout or killed in the terminal — the
ping fails, the status turns to stopped and every action is disabled.

## Ending the session

Revocation kills tokens, not the login: the provider still recognises the
browser and hands out a new grant without a prompt. Ending the session
instead uses RP-initiated logout, opened in a new tab so the result page
keeps pinging and stays open. It asks first, since the single sign-on
session it ends belongs to every application using it, not just this one.
`--post-logout-redirect` is off by default because providers reject the
parameter unless it is registered.

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

## Settings

Connection settings come from flags, `OAUTHENTICATOR_*` variables in the
process environment, and the same variables in an env file — `.env` in the
current directory by default, `--env-file` for another one. A flag wins over
the process environment, which wins over the file, which wins over the
built-in default. An empty variable still hides the sources below it, so
`export OAUTHENTICATOR_CLIENT_SECRET=` runs as a public client without editing
`.env`; the empty value then falls back to the built-in default, or to no value
at all. A missing default `.env` is skipped, a missing `--env-file` is an
error. Per-run switches
(`--no-browser`, `--stdout`, `--idle-timeout`, `-v`) are flags only.

`OAUTHENTICATOR_ADD_SCOPE` is appended before every `--add-scope`, rather than
replaced by them.

The redirect URI, when given explicitly from any source, is used as is, and a
host or port set anywhere is ignored with a warning. Otherwise it is built as
`http://<host>:<port>/callback` from `--host` and `--port`, `localhost` and
`8765` by default. The server binds to the redirect URI's host and port and
never falls back to another port, since providers compare the redirect URI
exactly; a taken port stops the run before discovery with a message.

`--client-secret` on the command line lands in shell history and is visible in
`ps`; `OAUTHENTICATOR_CLIENT_SECRET` avoids both, and `--help` never shows its
value.
