from fastapi import APIRouter
from app.crud.user_crud import UserCRUD
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect, Depends, status
from app.services.websocket_service import websocket_manager
from app.crud.user_crud import UserCRUD
import json
from app.config import settings
from jose import  jwt




# Create the router
ws_router = APIRouter(prefix="/ws", tags=["Websocket"])



# Web Socket Endpoints
@ws_router.websocket("/alerts/{token}")
async def websocket_alerts_authenticated(websocket: WebSocket,token:str):
    """WebSocket endpoint for authenticated user alerts"""
    # Verify token
    
    payload = jwt.decode(
            token, 
            settings.secret_key, 
            algorithms=[settings.algorithm]
    )
        
        
        # Extract user info from token
    user_id: str = payload.get("sub")
    user_crud=  UserCRUD()
    user=await user_crud.get_user_by_id(user_id=user_id)
        
    
    user_id, username = user.id,user.username
    
    if not user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    await websocket_manager.connect(websocket, user_id)
    
    try:
        # Send welcome message
        welcome_message = {
            "type": "welcome",
            "message": f"Connected to threat intelligence alerts",
            "user_id": user_id,
            "username": username,
            "timestamp": datetime.utcnow().isoformat()
        }
        await websocket.send_text(json.dumps(welcome_message))
        
        while True:
            # Handle incoming messages
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "ping":
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat(),
                    "user_id": user_id
                }))
            elif message.get("type") == "subscribe":
                # Handle subscription updates
                await websocket.send_text(json.dumps({
                    "type": "subscription_updated",
                    "message": "Subscription preferences updated",
                    "timestamp": datetime.utcnow().isoformat()
                }))
                
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket, user_id)


# Health check endpoint for WebSocket service  
# @ws_router.get("/api/ws/health")
# async def websocket_health():
#     """WebSocket service health check"""
#     stats = websocket_manager.get_connection_stats()
#     return {
#         "status": "healthy",
#         "service": "websocket_alerts",
#         "timestamp": datetime.utcnow().isoformat(),
#         "connections": stats
#     }
 


# class Alert(BaseModel):
#     """Alert for matched keyword"""
#     user_id: str
#     message_id: int
#     channel_username: str
#     channel_display_name: str
#     matched_keyword: str
#     message_text: str
#     message_url: str
#     timestamp: datetime
#     sent: bool = False
#     created_at: datetime = None
    
 
# @ws_router.get("/api/ws/send-alert")
# async def trigger_fake_alert():
#     # Fake user (normally from DB)
#     user_crud = UserCRUD()
#     user = await user_crud.get_user_by_id("687620effcae33bf9555540a")

#     # Fake alert object
#     alert = Alert(
#             user_id=user.id,
#             message_id=4567,
#             channel_username="@fake_channel",
#             channel_display_name="Fake Channel",
#             matched_keyword="malware",
#             message_text="Suspicious activity detected in the channel. Please review immediately.",
#             message_url="http://example.com/message/4567",
#             timestamp=datetime.utcnow(),
#             sent=False,
#             created_at=datetime.utcnow()
#         )

#     success = await websocket_manager.send_alert(alert, user)
#     return {"sent": success, "user": user.dict(), "alert": alert.dict()}
