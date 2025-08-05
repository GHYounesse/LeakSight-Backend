
from fastapi.middleware.cors import CORSMiddleware
from app.crud.user_crud import UserCRUD
from datetime import datetime
from contextlib import asynccontextmanager
from app.models import UserInDB
from app.api import auth_router,  ioc_router,subs_router,enrichment_router, feeds_router,dashboard_router
from app.database import connect_to_mongo, close_mongo_connection
from fastapi import FastAPI,Query, WebSocket, WebSocketDisconnect, Depends, status
from app.services.websocket_service import websocket_manager
import json
from app.api.auth import get_current_active_user
from app.config import settings
from jose import  jwt

@asynccontextmanager
async def lifespan(app: FastAPI):
    
    print("🔄 Trying to connect to MongoDB...")
    await connect_to_mongo()
    print("✅ MongoDB connection setup complete")
    
    try:
        yield
    finally:
        await close_mongo_connection()


app = FastAPI(
    title="Threat Intelligence Monitoring API",
    description="Threat Intelligence Monitoring API",
    version="1.0.0",lifespan=lifespan
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:4200", "http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],
)




#Routers
# Register the routers
app.include_router(auth_router)

app.include_router(ioc_router)

app.include_router(subs_router)

app.include_router(enrichment_router)

app.include_router(feeds_router)

app.include_router(dashboard_router)


# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "message": "Threat Intelligence Auth API is running"}


# Web Socket Endpoints
@app.websocket("/ws/alerts/{token}")
async def websocket_alerts_authenticated(websocket: WebSocket,token:str):
    """WebSocket endpoint for authenticated user alerts"""
    # Verify token
    print("Made it here:")
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
@app.get("/api/ws/health")
async def websocket_health():
    """WebSocket service health check"""
    stats = websocket_manager.get_connection_stats()
    return {
        "status": "healthy",
        "service": "websocket_alerts",
        "timestamp": datetime.utcnow().isoformat(),
        "connections": stats
    }




