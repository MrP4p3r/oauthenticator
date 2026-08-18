"""FastAPI application factory.

Route registration happens here, not at import time, because the callback
path comes from --redirect-uri and is only known once the CLI has parsed
its arguments -- there is no module-level app, only this factory.
"""

from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from oauthenticator.ui.web import renderer
from oauthenticator.ui.web.viewmodels import PathsView
from oauthenticator.web.routes import callback, page, ping
from oauthenticator.web.routes.api import introspect, quit as quit_route, refresh, revoke, userinfo

STATIC_PATH = '/static'


class RevalidatedStatic(StaticFiles):
    """Serves the page's own CSS and JS with revalidation forced on every load.

    Starlette sends an ETag but no Cache-Control, and the two asset URLs never
    change, so a browser that saw an earlier run may reuse those files on its own
    freshness heuristic without asking -- drawing the current page with the
    previous version's stylesheet and script. no-cache only forbids that silence:
    the ETag still answers 304, so a loopback reload costs a header exchange.
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers['Cache-Control'] = 'no-cache'

        return response


def create_app(session, callback_path, stdout_mode):
    """Builds the app and wires every route to this run's one AuthSession."""
    paths = PathsView(
        root=page.ROOT_PATH, ping=ping.PING_PATH, quit=quit_route.QUIT_PATH,
        refresh=refresh.REFRESH_PATH, userinfo=userinfo.USERINFO_PATH,
        introspect=introspect.INTROSPECT_PATH, revoke=revoke.REVOKE_PATH,
        css=f'{STATIC_PATH}/app.css', js=f'{STATIC_PATH}/app.js')

    environment = renderer.build_environment()

    app = FastAPI()
    app.add_exception_handler(HTTPException, _flatten_http_exception)
    app.mount(STATIC_PATH, RevalidatedStatic(directory=renderer.static_directory()),
              name='static')

    app.include_router(page.build_router(session, paths, environment))
    app.include_router(callback.build_router(
        session, callback_path, stdout_mode, paths, environment))
    app.include_router(ping.build_router(session))
    app.include_router(quit_route.build_router(session))
    app.include_router(refresh.build_router(session))
    app.include_router(userinfo.build_router(session))
    app.include_router(introspect.build_router(session))
    app.include_router(revoke.build_router(session))

    return app


async def _flatten_http_exception(request, exc):
    """Keeps every error response shaped as {"error": ...}, matching the action endpoints."""
    return JSONResponse({'error': exc.detail}, status_code=exc.status_code)
