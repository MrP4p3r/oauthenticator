"""POST /api/revoke/{name} -- revokes one token at the provider."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.web.models import ActionRequest
from oauthenticator.web.security import action_token_dependency

REVOKE_PATH = '/api/revoke'
ROUTE_PATTERN = REVOKE_PATH + '/{name}'


def build_router(session):
    router = APIRouter()
    verify_action_token = action_token_dependency(session)

    @router.post(ROUTE_PATTERN)
    async def post_revoke(name: str, payload: ActionRequest = Depends(verify_action_token)):
        try:
            return await session.revoke(name)
        except (OAuth2Error, RuntimeError) as error:
            return JSONResponse({'error': str(error)}, status_code=502)

    return router
