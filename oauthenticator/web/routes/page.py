"""GET / -- the UI the user logs in to.

Renders the result page once tokens exist. Otherwise it starts a fresh
flow: state, nonce and code_verifier are regenerated so a callback still in
flight for a previous flow fails the state check instead of resurrecting
it, then the browser is sent to the (new) authorization URL.
"""

from fastapi import APIRouter
from fastapi.responses import RedirectResponse, Response

from oauthenticator.ui.web import renderer, viewmodels

ROOT_PATH = '/'


def build_router(session, paths):
    router = APIRouter()

    @router.get(ROOT_PATH)
    async def get_page():
        if session.tokens is not None:
            view = viewmodels.build_result_page(session, paths)

            return Response(renderer.render(view), media_type='text/html')

        session.restart()

        return RedirectResponse(session.authorization_url(), status_code=302)

    return router
