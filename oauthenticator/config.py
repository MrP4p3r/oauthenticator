"""RunConfig: parsed and validated settings for a single CLI run."""

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

LOG_LEVELS = (logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG)


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
    verbosity: int

    @property
    def redirect(self):
        return urlparse(self.redirect_uri)

    @property
    def has_valid_redirect_uri(self):
        redirect = self.redirect

        return redirect.scheme == 'http' and bool(redirect.hostname) and bool(redirect.port)

    @property
    def log_level(self):
        """Maps the -v repeat count onto the logging ladder, clamping past -vvv to DEBUG."""
        return LOG_LEVELS[min(self.verbosity, len(LOG_LEVELS) - 1)]
