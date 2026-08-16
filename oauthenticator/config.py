"""RunConfig: parsed and validated settings for a single CLI run."""

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class RunConfig:
    issuer: str
    client_id: str
    client_secret: str | None
    scope: str
    redirect_uri: str
    no_browser: bool
    stdout: bool
    idle_timeout: float
    post_logout_redirect: str | None

    @property
    def redirect(self):
        return urlparse(self.redirect_uri)

    @property
    def has_valid_redirect_uri(self):
        redirect = self.redirect

        return redirect.scheme == 'http' and bool(redirect.hostname) and bool(redirect.port)
