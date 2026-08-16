"""GET /ping -- records a ping, keeping the CLI alive while the page is open."""

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

PING_PATH = '/ping'


def build_router(session):
    router = APIRouter()

    @router.get(PING_PATH)
    async def get_ping():
        session.ping()

        return PlainTextResponse('ok')

    return router
