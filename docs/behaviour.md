# Behaviour

A development CLI for the OAuth2/OIDC authorization code flow. It discovers
the provider config, opens the authorization URL in a browser, catches the
callback on a local HTTP server, and shows the tokens together with their
decoded JWT parts. It stays alive while the page is open, so the issued
tokens can be refreshed, introspected and revoked from it.

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
