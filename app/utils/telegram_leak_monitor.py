#!/usr/bin/env python3
"""
Multi-User Telegram Channel Monitor with Keyword Alerts
- Users can register and choose channels to monitor
- Users can set custom keywords for alerts
- Real-time notifications when keywords are found
"""
from bson import ObjectId
import asyncio
import logging
import os
import sys
from app.database import db
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, asdict
from telethon import TelegramClient
from telethon.tl.types import Channel, User
from telethon.errors import FloodWaitError, ChannelPrivateError, ChatAdminRequiredError
from pymongo.errors import  DuplicateKeyError
from dotenv import load_dotenv
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.database import connect_to_mongo, close_mongo_connection
from app.services.websocket_service import websocket_manager
load_dotenv()

# Streamlined logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('telegram_monitor.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Set console encoding for Windows
if sys.platform == 'win32':
    import os
    os.system('chcp 65001 > nul')

@dataclass
class MongoConfig:
    """MongoDB configuration"""
    host: str = 'localhost'
    port: int = 27017
    database: str = 'threat_intel'
    username: Optional[str] = None
    password: Optional[str] = None
    auth_source: Optional[str] = None

@dataclass
class UserKeyword:
    """User keyword configuration"""
    keyword: str
    case_sensitive: bool = False
    whole_word: bool = False
    regex: bool = False

@dataclass
class User:
    """User configuration"""
    user_id: str
    username: str
    email: str
    telegram_user_id: Optional[int] = None
    phone: Optional[str] = None
    enabled: bool = True
    created_at: datetime = None
    last_active: datetime = None

@dataclass
class UserChannelSubscription:
    """User's channel subscription with keywords"""
    user_id: str
    channel_username: str
    keywords: List[UserKeyword]
    enabled: bool = True
    created_at: datetime = None
    updated_at: Optional[datetime] = None

@dataclass
class Alert:
    """Alert for matched keyword"""
    user_id: str
    message_id: int
    channel_username: str
    channel_display_name: str
    matched_keyword: str
    message_text: str
    message_url: str
    timestamp: datetime
    sent: bool = False
    created_at: datetime = None

class NotificationService:
    """Handle different types of notifications"""
    
    def __init__(self, smtp_host: str = None, smtp_port: int = 587, 
                 smtp_user: str = None, smtp_pass: str = None,ws_manager=None
                 ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.ws_manager = websocket_manager
        
    
    async def send_websocket_alert(self, user: User, alert: Alert):
        """Send real-time WebSocket alert"""
        try:
            if not self.ws_manager:
                logger.warning("WebSocket manager not configured")
                return False
                
            success = await self.ws_manager.send_alert(alert, user)
            
            if success:
                logger.info(f"🌐 WebSocket alert sent to {user.username} for keyword '{alert.matched_keyword}'")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ WebSocket alert error: {e}")
            return False
    async def send_email_alert(self, user: User, alert: Alert):
        """Send styled email notification"""
        try:
            if not all([self.smtp_host, self.smtp_user, self.smtp_pass, user.email]):
                return False
                            
            msg = MIMEMultipart('alternative')
            msg['From'] = self.smtp_user
            msg['To'] = user.email
            msg['Subject'] = f"🚨 THREAT ALERT: '{alert.matched_keyword}' detected"
            
            # Plain text version (fallback)
            text_body = f"""
            THREAT INTELLIGENCE ALERT
            
            Hello {user.username},
            
            Your monitored keyword '{alert.matched_keyword}' was detected in:
            Channel: {alert.channel_display_name} (@{alert.channel_username})
            Detection Time: {alert.timestamp}
            
            Message Content:
            {alert.message_text[:500]}{'...' if len(alert.message_text) > 500 else ''}
            
            View Original Message: {alert.message_url}
            
            This is an automated alert from your Threat Intelligence Monitoring System.
            
            Best regards,
            Threat Intelligence Team
            """
            
            # HTML version with styling
            html_body = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Threat Intelligence Alert</title>
                <style>
                    * {{
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }}
                    
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
                        color: #ffffff;
                        line-height: 1.6;
                        padding: 20px;
                    }}
                    
                    .email-container {{
                        max-width: 600px;
                        margin: 0 auto;
                        background: #1a1a2e;
                        border-radius: 12px;
                        overflow: hidden;
                        box-shadow: 0 4px 20px rgba(0, 212, 255, 0.1);
                        border: 1px solid #333366;
                    }}
                    
                    .header {{
                        background: linear-gradient(135deg, #e94560, #dc2626);
                        padding: 30px 20px;
                        text-align: center;
                        position: relative;
                        overflow: hidden;
                    }}
                    
                    .header::before {{
                        content: '';
                        position: absolute;
                        top: 0;
                        left: 0;
                        right: 0;
                        bottom: 0;
                        background: radial-gradient(circle at 50% 50%, rgba(255, 255, 255, 0.1) 0%, transparent 70%);
                    }}
                    
                    .alert-icon {{
                        font-size: 3rem;
                        margin-bottom: 10px;
                        display: block;
                        position: relative;
                        z-index: 1;
                    }}
                    
                    .header h1 {{
                        color: #ffffff;
                        font-size: 1.8rem;
                        font-weight: 700;
                        text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
                        position: relative;
                        z-index: 1;
                    }}
                    
                    .content {{
                        padding: 30px 25px;
                    }}
                    
                    .greeting {{
                        font-size: 1.1rem;
                        color: #f8f9fa;
                        margin-bottom: 25px;
                    }}
                    
                    .alert-details {{
                        background: #16213e;
                        border-radius: 8px;
                        padding: 20px;
                        margin: 20px 0;
                        border-left: 4px solid #7de6e7;
                    }}
                    
                    .alert-item {{
                        display: flex;
                        justify-content: space-between;
                        align-items: flex-start;
                        margin-bottom: 15px;
                        padding-bottom: 10px;
                        border-bottom: 1px solid #333366;
                    }}
                    
                    .alert-item:last-child {{
                        margin-bottom: 0;
                        padding-bottom: 0;
                        border-bottom: none;
                    }}
                    
                    .alert-label {{
                        font-weight: 600;
                        color: #b0b0b0;
                        min-width: 120px;
                        font-size: 0.95rem;
                    }}
                    
                    .alert-value {{
                        color: #ffffff;
                        font-weight: 500;
                        flex: 1;
                        text-align: right;
                        word-break: break-word;
                    }}
                    
                    .keyword-highlight {{
                        background: linear-gradient(135deg, #f39c12, #ca8a04);
                        color: #0f0f23;
                        padding: 4px 8px;
                        border-radius: 4px;
                        font-weight: 700;
                        display: inline-block;
                    }}
                    
                    .channel-info {{
                        background: #0f3460;
                        color: #7de6e7;
                        padding: 4px 8px;
                        border-radius: 4px;
                        font-family: monospace;
                    }}
                    
                    .message-content {{
                        background: #0f0f23;
                        border-radius: 8px;
                        padding: 20px;
                        margin: 25px 0;
                        border: 1px solid #333366;
                    }}
                    
                    .message-content h3 {{
                        color: #7de6e7;
                        font-size: 1.1rem;
                        margin-bottom: 15px;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }}
                    
                    .message-text {{
                        color: #f8f9fa;
                        font-size: 0.95rem;
                        line-height: 1.7;
                        background: #16213e;
                        padding: 15px;
                        border-radius: 6px;
                        border-left: 3px solid #7de6e7;
                        font-family: 'Courier New', monospace;
                        white-space: pre-wrap;
                    }}
                    
                    .action-button {{
                        display: inline-block;
                        background: linear-gradient(135deg, #7de6e7, #0f3460);
                        color: #0f0f23;
                        padding: 12px 24px;
                        border-radius: 8px;
                        text-decoration: none;
                        font-weight: 600;
                        margin: 20px 0;
                        transition: all 0.3s ease;
                        box-shadow: 0 4px 15px rgba(125, 230, 231, 0.2);
                    }}
                    
                    .action-button:hover {{
                        transform: translateY(-2px);
                        box-shadow: 0 8px 25px rgba(125, 230, 231, 0.3);
                    }}
                    
                    .footer {{
                        background: #0f0f23;
                        padding: 25px;
                        text-align: center;
                        border-top: 1px solid #333366;
                    }}
                    
                    .footer-text {{
                        color: #6c757d;
                        font-size: 0.9rem;
                        margin-bottom: 10px;
                    }}
                    
                    .system-info {{
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-top: 15px;
                        padding-top: 15px;
                        border-top: 1px solid #333366;
                        font-size: 0.85rem;
                        color: #6c757d;
                    }}
                    
                    .status-indicator {{
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }}
                    
                    .status-dot {{
                        width: 8px;
                        height: 8px;
                        border-radius: 50%;
                        background: #00ff88;
                        box-shadow: 0 0 10px #00ff88;
                        animation: pulse 2s infinite;
                    }}
                    
                    @keyframes pulse {{
                        0%, 100% {{ opacity: 1; }}
                        50% {{ opacity: 0.5; }}
                    }}
                    
                    .severity-high {{
                        color: #ea580c;
                        font-weight: 700;
                    }}
                    
                    .severity-medium {{
                        color: #ca8a04;
                        font-weight: 600;
                    }}
                    
                    .severity-low {{
                        color: #16a34a;
                        font-weight: 500;
                    }}
                    
                    @media only screen and (max-width: 600px) {{
                        .email-container {{
                            margin: 10px;
                            border-radius: 8px;
                        }}
                        
                        .content {{
                            padding: 20px 15px;
                        }}
                        
                        .alert-item {{
                            flex-direction: column;
                            gap: 8px;
                        }}
                        
                        .alert-value {{
                            text-align: left;
                        }}
                        
                        .system-info {{
                            flex-direction: column;
                            gap: 10px;
                            text-align: center;
                        }}
                    }}
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="header">
                        <div class="alert-icon">🚨</div>
                        <h1>THREAT INTELLIGENCE ALERT</h1>
                    </div>
                    
                    <div class="content">
                        <div class="greeting">
                            Hello <strong>{user.username}</strong>,
                        </div>
                        
                        <p style="color: #f8f9fa; margin-bottom: 20px; font-size: 1.05rem;">
                            Your monitored keyword has been detected in a Telegram channel. 
                            Immediate attention may be required.
                        </p>
                        
                        <div class="alert-details">
                            <div class="alert-item">
                                <span class="alert-label">🎯 Keyword:</span>
                                <span class="alert-value">
                                    <span class="keyword-highlight">{alert.matched_keyword}</span>
                                </span>
                            </div>
                            
                            <div class="alert-item">
                                <span class="alert-label">📺 Channel:</span>
                                <span class="alert-value">
                                    {alert.channel_display_name}<br>
                                    <span class="channel-info">@{alert.channel_username}</span>
                                </span>
                            </div>
                            
                            <div class="alert-item">
                                <span class="alert-label">⏰ Detection Time:</span>
                                <span class="alert-value">{alert.timestamp}</span>
                            </div>
                            
                            <div class="alert-item">
                                <span class="alert-label">🔍 Severity:</span>
                                <span class="alert-value severity-high">HIGH PRIORITY</span>
                            </div>
                        </div>
                        
                        <div class="message-content">
                            <h3>📄 Intercepted Message Content:</h3>
                            <div class="message-text">{alert.message_text[:500]}{'...' if len(alert.message_text) > 500 else ''}</div>
                        </div>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{alert.message_url}" class="action-button">
                                🔗 View Original Message
                            </a>
                        </div>
                        
                        <div style="background: #16213e; padding: 15px; border-radius: 8px; border-left: 4px solid #f39c12;">
                            <p style="color: #f39c12; font-weight: 600; margin-bottom: 8px;">⚠️ Security Notice:</p>
                            <p style="color: #b0b0b0; font-size: 0.95rem;">
                                This alert was generated by your automated threat intelligence monitoring system. 
                                Please verify the context and take appropriate action if necessary.
                            </p>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <div class="footer-text">
                            This is an automated alert from your <strong>Threat Intelligence Monitoring System</strong>
                        </div>
                        
                        <div class="system-info">
                            <div class="status-indicator">
                                <div class="status-dot"></div>
                                <span>System Status: ONLINE</span>
                            </div>
                            <div>Alert ID: #TI-{alert.id if hasattr(alert, 'id') else 'UNKNOWN'}</div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Create message parts
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            
            # Attach parts
            msg.attach(part1)
            msg.attach(part2)
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_smtp_email, msg)
            
            logger.info(f"📧 Styled email alert sent to {user.email} for keyword '{alert.matched_keyword}'")
            return True
            
        except Exception as e:
            logger.error(f"❌ Email send error: {e}")
            return False
    def _send_smtp_email(self, msg):
        """Send SMTP email in thread"""
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.starttls()
            server.login(self.smtp_user, self.smtp_pass)
            server.send_message(msg)
    async def send_all_alerts(self, user: User, alert: Alert):
        """Send both email and WebSocket alerts"""
        email_sent = await self.send_email_alert(user, alert)
        websocket_sent = await self.send_websocket_alert(user, alert)
        
        return {
            "email_sent": email_sent,
            "websocket_sent": websocket_sent,
            "any_sent": email_sent or websocket_sent
        }


class MultiUserTelegramMonitor:
    """Multi-user Telegram Channel Monitor with Keyword Alerts"""
    
    def __init__(self, api_id: str, api_hash: str, phone: str):
        self.api_id = api_id
        self.api_hash = api_hash
        self.phone = phone
        self.client = TelegramClient('monitor_session', api_id, api_hash)
        
        
        
        # Cache
        self.channel_entities = {}
        self.processed_messages: Set[int] = set()
        self.last_check_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        
        # Notification service
        self.notification_service = NotificationService(
            smtp_host=os.getenv('SMTP_SERVER'),
            smtp_port=int(os.getenv('SMTP_PORT', 587)),
            smtp_user=os.getenv('SMTP_USERNAME'),
            smtp_pass=os.getenv('SMTP_PASSWORD'),
            ws_manager=websocket_manager

        )
        
        
    async def setup(self):
        """Initialize the system"""
        try:
            logger.info("🚀 Starting Multi-User Telegram Monitor...")
            
            # Setup MongoDB
            #await self.setup_mongodb()
            await connect_to_mongo()
            # Setup Telegram client
            await self.client.start(phone=os.getenv('TELEGRAM_PHONE'))
            logger.info("✅ Connected to Telegram")
            
            # Get self info
            me = await self.client.get_me()
            logger.info(f"👤 Logged in as: {me.username} ({me.first_name})")
            
            logger.info("✅ Setup complete")
            
        except Exception as e:
            logger.error(f"❌ Setup failed: {e}")
            raise
    

    
    async def get_all_users(self) -> List[User]:
        """Get all users"""
        try:
            
            users_data = await db.users_col.find({},  # Filter (empty means all)
            {"_id": 1, "email": 1, "username": 1}).to_list(length=None)
            for user in users_data:
                user["user_id"] = str(user["_id"])
                del user["_id"]
            return [User(**user) for user in users_data]
        except Exception as e:
            logger.error(f"❌ Get users error: {e}")
            return []
    
    async def subscribe_user_to_channel(self, user_id: str, channel_username: str, keywords: List[Dict]) -> bool:
        """Subscribe user to a channel with keywords"""
        try:
            # Convert keyword dicts to UserKeyword objects
            user_keywords = [UserKeyword(**kw) for kw in keywords]
            
            subscription = UserChannelSubscription(
                user_id=user_id,
                channel_username=channel_username.replace('@', ''),
                keywords=user_keywords,
                created_at=datetime.utcnow()
            )
            
            loop = asyncio.get_event_loop()
            #await loop.run_in_executor(None, db.subscriptions.insert_one, asdict(subscription))
            await db.subscriptions.insert_one(asdict(subscription))
            logger.info(f"📺 User {user_id} subscribed to @{channel_username} with {len(keywords)} keywords")
            return True
            
        except DuplicateKeyError:
            # Update existing subscription
            return await self.update_user_subscription(user_id, channel_username, keywords)
        except Exception as e:
            logger.error(f"❌ Subscription error: {e}")
            return False
    
    async def update_user_subscription(self, user_id: str, channel_username: str, keywords: List[Dict]) -> bool:
        """Update user's subscription keywords"""
        try:
            user_keywords = [UserKeyword(**kw) for kw in keywords]
            
            loop = asyncio.get_event_loop()
            
            filter_query = {
            "user_id": user_id,
            "channel_username": channel_username.lstrip('@')  # Safer than replace
            }

            # Update keywords
            result = await db.subscriptions.update_one(
                filter_query,
                {"$set": {"keywords": [kw.dict() if hasattr(kw, "dict") else asdict(kw) for kw in user_keywords]}}
            )
            
            if result.modified_count > 0:
                logger.info(f"📝 Updated subscription for {user_id} on @{channel_username}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"❌ Subscription update error: {e}")
            return False
    
    async def get_all_monitored_channels(self) -> Set[str]:
        """Get all channels that users are subscribed to"""
        try:
            loop = asyncio.get_event_loop()
            channels = await db.subscriptions.distinct("channel_username", {"enabled": True})
            return set(channels)
        except Exception as e:
            logger.error(f"❌ Get channels error: {e}")
            return set()
    
    async def get_channel_subscriptions(self, channel_username: str) -> List[UserChannelSubscription]:
        """Get all user subscriptions for a channel"""
        try:
            loop = asyncio.get_event_loop()
            subs_data = await db.subscriptions.find({
                "channel_username": channel_username,
                "enabled": True
            }).to_list(length=None)  # or a specific number instead of None

            
            subscriptions = []
            for sub_data in subs_data:
                sub_data.pop('_id', None)
                # Convert keyword dicts back to UserKeyword objects
                keywords = [UserKeyword(**kw) for kw in sub_data.get('keywords', [])]
                sub_data['keywords'] = keywords
                subscriptions.append(UserChannelSubscription(**sub_data))
            
            return subscriptions
            
        except Exception as e:
            logger.error(f"❌ Get subscriptions error: {e}")
            return []
    
    def check_keyword_match(self, text: str, keyword_obj: UserKeyword) -> bool:
        """Check if text matches keyword criteria"""
        if not text:
            return False
            
        keyword = keyword_obj.keyword
        
        if keyword_obj.regex:
            try:
                pattern = re.compile(keyword, re.IGNORECASE if not keyword_obj.case_sensitive else 0)
                return bool(pattern.search(text))
            except re.error:
                logger.warning(f"⚠️ Invalid regex pattern: {keyword}")
                return False
        
        search_text = text if keyword_obj.case_sensitive else text.lower()
        search_keyword = keyword if keyword_obj.case_sensitive else keyword.lower()
        
        if keyword_obj.whole_word:
            pattern = r'\b' + re.escape(search_keyword) + r'\b'
            flags = 0 if keyword_obj.case_sensitive else re.IGNORECASE
            return bool(re.search(pattern, search_text, flags))
        else:
            return search_keyword in search_text
    
    async def process_message_for_alerts(self, message, channel_username: str, channel_display_name: str):
        """Process message and create alerts for matching keywords"""
        try:
            # Get all subscriptions for this channel
            subscriptions = await self.get_channel_subscriptions(channel_username)
            
            if not subscriptions:
                return
            
            message_text = message.text or ""
            message_url = f"https://t.me/{channel_username}/{message.id}"
            
            alerts_created = 0
            
            for subscription in subscriptions:
                for keyword_obj in subscription.keywords:
                    if self.check_keyword_match(message_text, keyword_obj):
                        # Create alert
                        print(f"!!! Match for {keyword_obj}")
                        alert = Alert(
                            user_id=subscription.user_id,
                            message_id=message.id,
                            channel_username=channel_username,
                            channel_display_name=channel_display_name,
                            matched_keyword=keyword_obj.keyword,
                            message_text=message_text,
                            message_url=message_url,
                            timestamp=message.date,
                            created_at=datetime.utcnow()
                        )
                        
                        # Save alert to database
                        created=await self.save_alert(alert)
                        if created:
                        # Send notification
                            await self.send_alert_notification(alert)
                        
                            alerts_created += 1
                            logger.info(f"🚨 Alert created: User {subscription.user_id} - Keyword '{keyword_obj.keyword}'")
                        else:
                            logger.info(f"🚨 Alert already has been sent: User {subscription.user_id} - Keyword '{keyword_obj.keyword}'")
            
            if alerts_created > 0:
                logger.info(f"📨 Message ID {message.id}: {alerts_created} alerts created")
                
        except Exception as e:
            logger.error(f"❌ Error processing message for alerts: {e}")
    
    
    from dataclasses import asdict

    async def save_alert(self, alert: Alert) -> bool:
        """Save alert to database if it doesn't already exist"""
        try:
            # Define the unique filter
            query = {
                "user_id": alert.user_id,
                "message_id": alert.message_id,
                "channel_username": alert.channel_username
            }

            # Check if the alert already exists
            existing = await db.alerts.find_one(query)
            if existing:
                logger.info("🔁 Duplicate alert found, skipping save.")
                return False

            # Save the new alert
            await db.alerts.insert_one(asdict(alert))
            logger.info("✅ Alert saved.")
            return True

        except Exception as e:
            logger.error(f"❌ Save alert error: {e}")
            return False

    
    
    async def send_alert_notification(self, alert: Alert):
        """Send notification for alert"""
        try:
            # Get user info
            user_data = await db.users_col.find_one({"_id": ObjectId(alert.user_id)})

            if not user_data:
                logger.error(f"❌ User not found: {alert.user_id}")
                return
            expected_fields = {
                "user_id": str(user_data.get("_id")),
                "username": user_data.get("username"),
                "email": user_data.get("email"),
                "telegram_user_id": user_data.get("telegram_user_id"),
                "phone": user_data.get("phone"),
                "enabled": user_data.get("is_active", True),
                "created_at": user_data.get("created_at"),
                "last_active": user_data.get("last_login"),
            }

            user = User(**expected_fields)
            

            
            results = await self.notification_service.send_all_alerts(user, alert)

            # Update alert as sent if any notification method succeeded
            if results["any_sent"]:
                alert_data = await db.alerts.find_one({
                    "user_id": alert.user_id,
                    "message_id": alert.message_id,
                    "created_by": {"$ne": -1}
                })
                if alert_data:
                    await db.alerts.update_one(
                        {"_id": alert_data["_id"]},
                        {"$set": {
                            "sent": True,
                            "email_sent": results["email_sent"],
                            "websocket_sent": results["websocket_sent"],
                            "notification_timestamp": datetime.utcnow()
                        }}
                    )

            logger.info(f"📊 Alert notifications sent - Email: {results['email_sent']}, WebSocket: {results['websocket_sent']}")

        except Exception as e:
            logger.error(f"❌ Send notification error: {e}")

    async def verify_and_cache_channels(self, channels: Set[str]):
        """Verify channels and cache entities"""
        verified_channels = set()
        
        logger.info(f"🔍 Verifying {len(channels)} channels...")
        
        for channel_username in channels:
            try:
                entity = None
                try:
                    entity = await self.client.get_entity(channel_username)
                except Exception:
                    try:
                        entity = await self.client.get_entity(f"@{channel_username}")
                    except Exception:
                        logger.warning(f"⚠️ Cannot access channel: @{channel_username}")
                        continue
                
                if entity and isinstance(entity, Channel):
                    verified_channels.add(channel_username)
                    self.channel_entities[channel_username] = entity
                    logger.info(f"✅ Verified: @{channel_username}")
                        
            except (ChannelPrivateError, ChatAdminRequiredError):
                logger.warning(f"🔒 Access denied: @{channel_username}")
            except Exception as e:
                logger.warning(f"❌ Error verifying @{channel_username}: {e}")
        
        logger.info(f"✅ {len(verified_channels)} channels verified")
        return verified_channels
    
    async def poll_channels(self):
        """Poll all subscribed channels for new messages"""
        current_time = datetime.now(timezone.utc)
        monitored_channels = await self.get_all_monitored_channels()
        users = await self.get_all_users()
        
        if not monitored_channels:
            print("❌ No channels to monitor. Please add some subscriptions first.")
            return 0
        
        if not users:
            print("❌ No users registered. Please register users first.")
            return 0
        
        print(f"\n🚀 Ready to start monitoring:")
        print(f"   👥 Users: {len(users)}")
        print(f"   📺 Channels: {len(monitored_channels)}")
        print(f"   🔄 Check interval: 15 minutes")
        # Get all channels that users are subscribed to
        
        
        # Verify channels
        verified_channels = await self.verify_and_cache_channels(monitored_channels)
        
        if not verified_channels:
            logger.warning("⚠️ No accessible channels to monitor")
            return 0
        
        logger.info(f"🔍 Polling {len(verified_channels)} channels for new messages...")
        logger.info(f"🕐 Last check time: {self.last_check_time}")
        
        total_new_messages = 0
        
        for channel_username in verified_channels:
            try:
                entity = self.channel_entities.get(channel_username)
                if not entity:
                    continue
                
                channel_messages = 0
                
                # Get messages since last check
                async for message in self.client.iter_messages(entity, limit=50):
                    message_time = self._to_utc_aware(message.date)
                    
                    # Break if message is older than last check time
                    if message_time <= self.last_check_time:
                        break
                    
                    
                    # Process for alerts
                    await self.process_message_for_alerts(message, channel_username, entity.title or channel_username)
                    
                    channel_messages += 1
                
                if channel_messages > 0:
                    total_new_messages += channel_messages
                    logger.info(f"   📺 @{channel_username}: {channel_messages} new messages")
                
            except FloodWaitError as e:
                logger.warning(f"⏳ Rate limited on @{channel_username}: waiting {min(e.seconds, 300)} seconds")
                await asyncio.sleep(min(e.seconds, 300))
            except Exception as e:
                logger.warning(f"❌ Error polling @{channel_username}: {e}")
        
        self.last_check_time = current_time
        
        if total_new_messages > 0:
            logger.info(f"✅ Poll complete: {total_new_messages} new messages processed")
        else:
            logger.info("✅ Poll complete: No new messages found")
        
        return total_new_messages
    
    async def save_message(self, message, channel_username: str, channel_display_name: str):
        """Save message to database"""
        try:
            document = {
                'message_id': message.id,
                'timestamp': message.date,
                'channel_username': channel_username,
                'channel_display_name': channel_display_name,
                'sender': getattr(message.sender, 'username', 'Unknown') if message.sender else 'Channel',
                'text': message.text or "",
                'text_length': len(message.text or ""),
                'has_media': bool(message.media),
                'views': getattr(message, 'views', 0),
                'forwards': getattr(message, 'forwards', 0),
                'processed_at': datetime.utcnow(),
                'url': f"https://t.me/{channel_username}/{message.id}"
            }
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._insert_message, document)
            
        except Exception as e:
            logger.error(f"❌ Error saving message: {e}")
    
    def _insert_message(self, document: Dict):
        """Insert message into MongoDB"""
        try:
            db.messages.insert_one(document)
        except DuplicateKeyError:
            pass  # Message already exists
        except Exception as e:
            logger.error(f"MongoDB insert error: {e}")
    
    async def start_monitoring(self):
        """Start the monitoring loop"""
        logger.info("🚀 Starting multi-user monitoring cycle...")
        
        print(f"\n{'='*60}")
        print(f"📊 MULTI-USER TELEGRAM MONITOR ACTIVE")
        print(f"🔄 Monitoring user-subscribed channels every 15 minutes")
        print(f"📝 Check telegram_monitor.log for details")
        print(f"⏹️  Press Ctrl+C to stop")
        print(f"{'='*60}")
        
        poll_count = 0
        
        try:
            while True:
                poll_count += 1
                logger.info(f"🔄 Starting poll #{poll_count}")
                
                start_time = datetime.now()
                new_messages = await self.poll_channels()
                duration = (datetime.now() - start_time).total_seconds()
                
                logger.info(f"📊 Poll #{poll_count} completed in {duration:.1f}s - {new_messages} new messages")
                
                # Wait 15 minutes before next poll
                logger.info("⏰ Waiting 15 minutes until next poll...")
                await asyncio.sleep(900)  # 15 minutes

        except KeyboardInterrupt:
            logger.info("🛑 Monitoring stopped by user")
        except Exception as e:
            logger.error(f"❌ Fatal error in monitoring loop: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.client.is_connected():
            await self.client.disconnect()
            logger.info("✅ Disconnected from Telegram")
        
        await close_mongo_connection()
        logger.info("✅ Disconnected from MongoDB")
    
    def _to_utc_aware(self, dt):
        """Convert datetime to UTC aware datetime"""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)


class TelegramMonitorCLI:
    """Command Line Interface for managing the Telegram Monitor"""
    
    def __init__(self):
        self.monitor = None
        
    async def init_monitor(self):
        """Initialize the monitor"""
        API_ID = os.getenv("TELEGRAM_API_ID")
        API_HASH = os.getenv("TELEGRAM_API_HASH")
        PHONE = os.getenv("TELEGRAM_PHONE")
        
        if not API_ID or not API_HASH or not PHONE:
            print("❌ Please set your API credentials in environment variables:")
            print("   TELEGRAM_API_ID=your_api_id")
            print("   TELEGRAM_API_HASH=your_api_hash")
            print("   TELEGRAM_PHONE=your_phone_number")
            return False
        
        mongo_config = MongoConfig(
            host=os.getenv('MONGO_HOST', 'localhost'),
            port=int(os.getenv('MONGO_PORT', 27017)),
            database=os.getenv('MONGO_DATABASE', 'threat_intel'),
            # username=os.getenv('MONGO_USERNAME'),
            # password=os.getenv('MONGO_PASSWORD'),
            # auth_source=os.getenv('MONGO_AUTH_SOURCE')
        )
        
        self.monitor = MultiUserTelegramMonitor(API_ID, API_HASH, PHONE)
        await self.monitor.setup()
        return True
    
    
        
    
    async def run_cli(self):
        """Run the CLI interface"""
        print("🤖 Telegram Monitor CLI")
        print("=" * 40)
        
        if not await self.init_monitor():
            return
        
            
        try:        
                await self.monitor.start_monitoring()
                        
        except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                
        except Exception as e:
                print(f"❌ Error: {e}")
        
        if self.monitor:
            await self.monitor.cleanup()

async def main():
    """Main entry point"""
    
        
    cli = TelegramMonitorCLI()
    await cli.run_cli()

if __name__ == "__main__":
    asyncio.run(main())