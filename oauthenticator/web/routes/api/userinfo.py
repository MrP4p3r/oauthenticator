"""POST /api/userinfo -- (re)fetches userinfo for the current access token."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from oauthenticator.oauth2.errors import OAuth2Error
from oauthenticator.web.models import ActionRequest
from oauthenticator.web.security import action_token_dependency

USERINFO_PATH = '/api/userinfo'


def build_router(session):
    router = APIRouter()
    verify_action_token = action_token_dependency(session)

    @router.post(USERINFO_PATH)
    async def post_userinfo(payload: ActionRequest = Depends(verify_action_token)):
        try:
            await session.load_userinfo()
            if session.userinfo is None:
                raise RuntimeError(session.userinfo_error)
        except (OAuth2Error, RuntimeError) as error:
            return JSONResponse({'error': str(error)}, status_code=502)

        return session.userinfo

    return router
