from app.database import db
import aiohttp
from pydantic import BaseModel,validator
from datetime import datetime
from bson import ObjectId
from typing import List,Optional
from app.config import settings
from app.dependencies import logger 
GROQ_API_KEY = settings.GROQ_API_KEY
GROQ_API_URL = settings.GROQ_API_URL
MODEL = settings.MODEL

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
class RSSProcessor:     
    def __init__(self):
        
        if db.feeds is None:
            raise RuntimeError("Feeds collection not initialized")
        self.collection = db.feeds
        self.session = None
    
    async def __aenter__(self):
        # Create aiohttp session with retry logic
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=2)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                "User-Agent": "CyberFeedNormalizer/1.0"
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    
    async def search_feeds(
    self, 
    query: Optional[str] = None,
    priority: Optional[str] = None, 
    source: Optional[str] = None, 
    limit: int = 10, 
    skip: int = 0
    ):
        """
        Search feeds by query and filter by priority and/or source
        Only applies filters when parameters are not None/empty
        """
        try:
            # Build filter conditions - only add filters that have actual values
            filters = {}
            
            # Add text search only if query has content
            if query:
                filters['$or'] = [
                    {'title': {'$regex': query, '$options': 'i'}},
                    {'summary': {'$regex': query, '$options': 'i'}},
                    {'content': {'$regex': query, '$options': 'i'}}
                ]
            
            # Add priority filter only if priority is provided
            if priority:
                filters['priority'] = priority
                
            # Add source filter only if source is provided
            if source:
                filters['source'] = source
            
            # Debug logging (optional - remove in production)
            
            
            # Get total count with applied filters
            total_count = await self.collection.count_documents(filters)
            
            # Get filtered feeds with pagination
            cursor = self.collection.find(filters).sort("publishedDate", -1).skip(skip).limit(limit)
            feeds_data = await cursor.to_list(length=limit)
            
            feeds = []
            for feed in feeds_data:
                feed["_id"] = str(feed["_id"])  # Convert ObjectId to string
                feeds.append(FeedItem(**feed))
            return feeds, total_count
            
        except Exception as e:
            raise Exception(f"Error searching feeds: {str(e)}")
    
