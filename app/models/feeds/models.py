from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from pydantic import validator
from bson import ObjectId

class FeedItem(BaseModel):
    _id: str
    title: str
    link: str
    summary: Optional[str] = None   
    content: Optional[str] = None
    source: str
    categories: List[str]
    priority: str
    publishedDate: Optional[datetime] = None

    @validator('publishedDate', pre=True, always=True)
    def set_default_published_date(cls, v):
        if v is None:
            return datetime.utcnow()
        return v

    class Config:
        # Allow ObjectId to be converted to string
        json_encoders = {
            ObjectId: str
        }

class FeedResponse(BaseModel):
    items: List[FeedItem]
    total: int
    limit: int
    skip: int