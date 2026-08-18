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

Put the client settings into a `.env` in your project directory:

```sh
OAUTHENTICATOR_ISSUER=https://issuer.example.com
OAUTHENTICATOR_CLIENT_ID=my-client
OAUTHENTICATOR_CLIENT_SECRET=my-secret
OAUTHENTICATOR_ADD_SCOPE=offline_access
```

and run it there:

```sh
oauthenticator
```

The browser opens at the authorization URL; the URL is printed either way, so it can
be copied to another machine or reopened after the tab is lost. The CLI stays alive
while the page is open and exits once the page stops pinging.

Any setting can be overridden for a single run with a flag, e.g.
`oauthenticator --port 9000`. A flag wins over an exported `OAUTHENTICATOR_*`
variable, which wins over the `.env`. Read another file with `--env-file PATH`.
Everything also works with flags alone:

```sh
oauthenticator --issuer https://issuer.example.com --client-id my-client
```

Useful flags:

| flag | env variable | what it does |
|---|---|---|
| `--issuer` | `OAUTHENTICATOR_ISSUER` | OIDC issuer base URL, required |
| `--client-id` | `OAUTHENTICATOR_CLIENT_ID` | required |
| `--client-secret` | `OAUTHENTICATOR_CLIENT_SECRET` | omit for a public client |
| `--scope` | `OAUTHENTICATOR_SCOPE` | replaces the base scope set (default `openid email profile`) |
| `--add-scope` | `OAUTHENTICATOR_ADD_SCOPE` | appends to it, repeatable; a refresh token usually needs `offline_access` |
| `--redirect-uri` | `OAUTHENTICATOR_REDIRECT_URI` | must be registered at the provider; wins over `--host` and `--port` |
| `--host` | `OAUTHENTICATOR_HOST` | redirect URI host (default `localhost`) |
| `--port` | `OAUTHENTICATOR_PORT` | redirect URI port (default `8765`) |
| `--post-logout-redirect` | `OAUTHENTICATOR_POST_LOGOUT_REDIRECT` | where the provider sends the browser after ending the session |
| `--env-file` | | settings file to read (default `.env` in the current directory) |
| `--no-browser` | | do not open a browser |
| `--stdout` | | dump the result to the terminal instead of serving a page |
| `--idle-timeout` | | exit this long after the last ping from the page |
| `-v` | | repeatable: `-v` warnings, `-vv` info, `-vvv` debug; errors only by default |

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
