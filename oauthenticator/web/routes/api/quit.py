"""POST /api/quit -- signals the CLI to stop serving and exit."""

from fastapi import APIRouter, Depends

from oauthenticator.web.models import ActionRequest
from oauthenticator.web.security import action_token_dependency

QUIT_PATH = '/api/quit'


def build_router(session):
    router = APIRouter()
    verify_action_token = action_token_dependency(session)

    @router.post(QUIT_PATH)
    async def post_quit(payload: ActionRequest = Depends(verify_action_token)):
        session.finished.set()

        return {'status': 'finished'}

    return router
