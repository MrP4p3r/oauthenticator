"""POST /api/refresh -- replaces the whole token set.

Refresh sits in the top bar instead of a single token tab and reloads the
page, since it replaces every token at once rather than reporting on one.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.web.models import ActionRequest
from oauthenticator.web.security import action_token_dependency

REFRESH_PATH = '/api/refresh'


def build_router(session):
    router = APIRouter()
    verify_action_token = action_token_dependency(session)

    @router.post(REFRESH_PATH)
    async def post_refresh(payload: ActionRequest = Depends(verify_action_token)):
        try:
            return await session.refresh()
        except (OAuth2Error, RuntimeError) as error:
            return JSONResponse({'error': str(error)}, status_code=502)

    return router
