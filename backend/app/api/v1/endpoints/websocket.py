from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from app.core.websocket import ws_manager
from app.core.rbac import get_ws_current_user
from app.models.user import User

router = APIRouter()

@router.websocket("/ws/alerts")
async def alerts_websocket_endpoint(
    websocket: WebSocket,
    user: Optional[User] = Depends(get_ws_current_user)
):
    """
    Canonical WebSocket alert stream gateway.
    Requires authenticated bearer token via query param ?token=... or header.
    Unauthenticated connections are rejected with WS 1008 Policy Violation.
    """
    if user is None:
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
