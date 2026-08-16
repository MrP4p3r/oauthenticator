"""Action-token dependency, guarding the page's own action endpoints.

Every action POST carries a per-session action token, which stops another
origin from driving these endpoints on a known localhost port. It is a
FastAPI dependency rather than middleware, since only the /api/ routes need
it.
"""

import secrets

from fastapi import HTTPException

from oauthenticator.web.models import ActionRequest


def action_token_dependency(session):
    """Builds a dependency bound to this run's session and its action token."""

    async def verify_action_token(payload: ActionRequest) -> ActionRequest:
        if not secrets.compare_digest(payload.action_token, session.action_token):
            raise HTTPException(status_code=403, detail='bad action token')

        return payload

    return verify_action_token
