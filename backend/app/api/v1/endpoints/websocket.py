from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.websocket import ws_manager

router = APIRouter()

@router.websocket("/ws/alerts")
async def alerts_websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
