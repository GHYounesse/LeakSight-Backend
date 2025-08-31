
from typing import List
from pydantic import BaseModel
from dataclasses import dataclass
from datetime import datetime

class Keyword(BaseModel):
    keyword: str
    case_sensitive: bool = False
    regex: bool = False

class SubscribeRequest(BaseModel):
    #user_id: str
    channel_username: str
    keywords: List[Keyword]

class BulkSubscribeRequest(BaseModel):
    #user_id: str
    channel_usernames: List[str]
    keywords: List[Keyword]

class BulkUnsubscribeRequest(BaseModel):
    #user_id: str
    channel_usernames: List[str]

@dataclass
class UserKeyword:
    """User keyword configuration"""
    keyword: str
    case_sensitive: bool = False
    regex: bool = False



@dataclass
class UserChannelSubscription:
    """User's channel subscription with keywords"""
    user_id: str
    channel_username: str
    keywords: List[UserKeyword]
    enabled: bool = True
    created_at: datetime = None

