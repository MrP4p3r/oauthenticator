# oauthenticator

A development CLI for getting OAuth2/OIDC tokens out of a provider and looking at
them. Point it at an issuer and a client, it runs the authorization code flow with
PKCE, catches the callback on a local server, and opens a page where the tokens can
be inspected, refreshed, introspected and revoked.

It is a tool for development and debugging. Token decoding is deliberately
unverified — no key material is fetched — so the page shows expired, revoked and
malformed tokens rather than rejecting them. Never treat what it displays as
trusted.

## Install

From a clone of this repository:

```sh
uv tool install .
```

After pulling changes, run `uv tool install --reinstall .`.

## Usage

```sh
oauthenticator --issuer https://issuer.example.com --client-id my-client
```

The browser opens at the authorization URL; the URL is printed either way, so it can
be copied to another machine or reopened after the tab is lost. The CLI stays alive
while the page is open and exits once the page stops pinging.

Useful flags:

| flag | what it does |
|---|---|
| `--client-secret` | omit for a public client |
| `--scope` | replaces the base scope set (default `openid email profile`) |
| `--add-scope` | appends to it, repeatable; a refresh token usually needs `offline_access` |
| `--redirect-uri` | must be registered at the provider (default `http://localhost:8765/callback`) |
| `--no-browser` | do not open a browser |
| `--stdout` | dump the result to the terminal instead of serving a page |
| `--idle-timeout` | exit this long after the last ping from the page |
| `--post-logout-redirect` | where the provider sends the browser after ending the session |
| `-v` | repeatable: `-v` warnings, `-vv` info, `-vvv` debug; errors only by default |

Run `oauthenticator --help` for the full list.

## Development

```sh
uv sync
uv run pytest
```

The suite runs against an in-process fake OIDC provider reached through
`httpx.ASGITransport`, so no test touches the network.

See [docs/behaviour.md](docs/behaviour.md) for how the tool behaves, and
[docs/design/](docs/design/) for the web UI design.
