"""Builds the Jinja environment and renders result-page view models to HTML.

The environment is constructed once per run, not at import time, and handed
to the route builders that need it -- see web/app.py. Autoescaping is on, so
every `{{ }}` expression is HTML-escaped by default; nothing here uses `|safe`.
"""

import importlib.resources
import time

from jinja2 import Environment, PackageLoader, select_autoescape

from oauthenticator.oauth2.tokens import TIME_FORMAT

PING_INTERVAL = 5


def build_environment():
    """Constructs the Jinja environment for the result page and the notice card."""
    environment = Environment(
        loader=PackageLoader('oauthenticator.ui.web', 'templates'),
        autoescape=select_autoescape(['html', 'j2']),
        trim_blocks=True, lstrip_blocks=True)

    environment.filters['format_time'] = _format_time
    environment.filters['format_epoch'] = _format_epoch

    return environment


def static_directory():
    """Filesystem path to this package's static/ directory, wheel-install safe."""
    return str(importlib.resources.files('oauthenticator.ui.web') / 'static')


def render(environment, view):
    template = environment.get_template('result_page.html.j2')

    return template.render(view=view, ping_interval=PING_INTERVAL).encode()


def render_notice(environment, view):
    template = environment.get_template('notice.html.j2')

    return template.render(view=view).encode()


def _format_time(value):
    return time.strftime(TIME_FORMAT, time.gmtime(value))


def _format_epoch(value):
    return f'{value:.0f}'
