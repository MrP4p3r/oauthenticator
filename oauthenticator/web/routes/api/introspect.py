"""POST /api/introspect/{name} -- reports what the provider knows about one token."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.web.models import ActionRequest
from oauthenticator.web.security import action_token_dependency

INTROSPECT_PATH = '/api/introspect'
ROUTE_PATTERN = INTROSPECT_PATH + '/{name}'


def build_router(session):
    router = APIRouter()
    verify_action_token = action_token_dependency(session)

    @router.post(ROUTE_PATTERN)
    async def post_introspect(name: str, payload: ActionRequest = Depends(verify_action_token)):
        try:
            return await session.introspect(name)
        except (OAuth2Error, RuntimeError) as error:
            return JSONResponse({'error': str(error)}, status_code=502)

    return router
