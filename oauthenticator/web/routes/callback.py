"""GET <callback path> -- the provider's redirect target.

A protocol endpoint, not a page: it hands off to / on success, and renders
a page itself only in --stdout mode, where there is no UI to hand off to.
The path itself comes from --redirect-uri, so the route is registered here
at app-build time rather than declared as a constant.
"""

import urllib.parse

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from oauthenticator.ui.web import renderer, viewmodels
from oauthenticator.web.routes.page import ROOT_PATH


def build_router(session, callback_path, stdout_mode, paths):
    router = APIRouter()

    @router.get(callback_path)
    async def get_callback(request: Request):
        query = urllib.parse.parse_qs(request.url.query)
        accepted = await session.complete(query)

        if accepted:
            session.delivered.set()

        if stdout_mode:
            view = viewmodels.build_notice(session)

            return Response(renderer.render_notice(view), media_type='text/html')

        if session.tokens is not None and session.error is None:
            return RedirectResponse(ROOT_PATH, status_code=303)

        view = viewmodels.build_result_page(session, paths)

        return Response(renderer.render(view), media_type='text/html')

    return router
