# websocket_service.py
import json
import asyncio
import logging
from typing import Dict, List, Set
from fastapi import WebSocket
from datetime import datetime
from dataclasses import asdict

logger = logging.getLogger(__name__)

class WebSocketManager:
    """Manages WebSocket connections for real-time alerts"""
    
    def __init__(self):
        # Store active connections by user_id
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # Store all connections for broadcast
        self.all_connections: Set[WebSocket] = set()
        
    async def connect(self, websocket: WebSocket, user_id: str = None):
        """Accept a new WebSocket connection"""
        await websocket.accept()
        self.all_connections.add(websocket)
        
        if user_id:
            if user_id not in self.active_connections:
                self.active_connections[user_id] = []
            self.active_connections[user_id].append(websocket)
            
        logger.info(f"WebSocket connected for user: {user_id or 'anonymous'}")
        
    def disconnect(self, websocket: WebSocket, user_id: str = None):
        """Remove a WebSocket connection"""
        self.all_connections.discard(websocket)
        
        if user_id and user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                
        logger.info(f"WebSocket disconnected for user: {user_id or 'anonymous'}")
    
    async def send_personal_message(self, message: dict, user_id: str):
        """Send message to specific user's connections"""
        if user_id not in self.active_connections:
            return
            
        disconnected = []
        for websocket in self.active_connections[user_id]:
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Error sending message to {user_id}: {e}")
                disconnected.append(websocket)
        
        # Clean up disconnected websockets
        for ws in disconnected:
            self.disconnect(ws, user_id)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        if not self.all_connections:
            return
            
        disconnected = []
        for websocket in self.all_connections.copy():
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")
                disconnected.append(websocket)
        
        # Clean up disconnected websockets
        for ws in disconnected:
            self.all_connections.discard(ws)
    
    async def send_alert(self, alert, user):
        """Send alert via WebSocket"""
        try:
            alert_message = {
                "type": "threat_alert",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "id": getattr(alert, 'id', 'unknown'),
                    "user_id": alert.user_id,
                    "username": user.username,
                    "matched_keyword": alert.matched_keyword,
                    "channel_username": alert.channel_username,
                    "channel_display_name": alert.channel_display_name,
                    "message_text": alert.message_text[:500],
                    "message_url": alert.message_url,
                    "alert_timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                    #"severity": self._calculate_severity(alert.matched_keyword),
                    "severity":"HIGH",
                    "message_preview": alert.message_text[:100] + "..." if len(alert.message_text) > 100 else alert.message_text
                }
            }
            
            # Send to specific user
            await self.send_personal_message(alert_message, alert.user_id)
            
            # Also broadcast to admin/monitoring dashboard (optional)
            admin_message = {
                **alert_message,
                "type": "admin_alert",
                "data": {
                    **alert_message["data"],
                    "user_email": user.email
                }
            }
            
            # You can implement admin-specific broadcasting here
            # await self.broadcast_to_admins(admin_message)
            
            logger.info(f"WebSocket alert sent to user {user.username} for keyword '{alert.matched_keyword}'")
            return True
            
        except Exception as e:
            logger.error(f"Error sending WebSocket alert: {e}")
            return False
    
    # def _calculate_severity(self, keyword: str) -> str:
    #     """Calculate alert severity based on keyword"""
    #     high_priority_keywords = [
    #         'vulnerability', 'exploit', 'breach', 'malware', 'ransomware', 
    #         'zero-day', 'attack', 'hack', 'compromise', 'backdoor'
    #     ]
        
    #     medium_priority_keywords = [
    #         'threat', 'suspicious', 'phishing', 'scam', 'leak', 'exposure'
    #     ]
        
    #     keyword_lower = keyword.lower()
        
    #     if any(hp_keyword in keyword_lower for hp_keyword in high_priority_keywords):
    #         return "HIGH"
    #     elif any(mp_keyword in keyword_lower for mp_keyword in medium_priority_keywords):
    #         return "MEDIUM"
    #     else:
    #         return "LOW"
    
    def get_connection_stats(self) -> dict:
        """Get connection statistics"""
        return {
            "total_connections": len(self.all_connections),
            "user_connections": {user_id: len(connections) 
                               for user_id, connections in self.active_connections.items()},
            "users_online": len(self.active_connections)
        }

# Global WebSocket manager instance
websocket_manager = WebSocketManager()