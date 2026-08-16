"""Pydantic request models for the HTTP layer.

Every page action carries only the action token in its body -- the token
name, where one applies, moves into the URL path instead.
"""

from pydantic import BaseModel


class ActionRequest(BaseModel):
    """Body of every POST /api/... request."""

    action_token: str
