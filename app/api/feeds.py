from fastapi import APIRouter, Query, HTTPException, Depends
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from pydantic import validator
from bson import ObjectId

# Assuming you have these models defined somewhere
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
from app.api.auth import get_current_active_user
from app.models.auth import UserInDB
# Create the router
feeds_router = APIRouter(prefix="/api/v1/feeds", tags=["Feeds Management"])



from app.crud.rss_processor import RSSProcessor

@feeds_router.get("/", response_model=FeedResponse)
async def get_feeds(
    limit: int = Query(10, ge=1, le=100, description="Number of items to return"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Get all feeds with pagination
    """
    try:
        rss_processor = RSSProcessor()
        feeds, total_count = await rss_processor.get_feeds(limit, skip)
        
        # Convert FeedItem objects to dictionaries
        feed_dicts = [feed.dict() if hasattr(feed, 'dict') else feed.__dict__ for feed in feeds]
        
        return FeedResponse(
            items=feed_dicts,
            total=total_count,
            limit=limit,
            skip=skip
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching feeds: {str(e)}")
    
    
@feeds_router.get("/by-priority/{priority}", response_model=FeedResponse)
async def get_feeds_by_priority(
    priority: str,
    limit: int = Query(10, ge=1, le=100, description="Number of items to return"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Get feeds filtered by priority level
    """
    try:
        # Validate priority value
        valid_priorities = ["Low", "Medium", "High", "Information"]
        if priority not in valid_priorities:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid priority. Must be one of: {', '.join(valid_priorities)}"
            )
        
        rss_processor=RSSProcessor()
        feeds, total_count = await rss_processor.get_feeds_by_priority(priority, limit, skip)
        feeds = [feed.dict() for feed in feeds]
        
        return FeedResponse(
            items=feeds,
            total=total_count,
            limit=limit,
            skip=skip
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching feeds by priority: {str(e)}")

@feeds_router.get("/by-source/{source}", response_model=FeedResponse)
async def get_feeds_by_source(
    source: str,
    limit: int = Query(10, ge=1, le=100, description="Number of items to return"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Get feeds filtered by source
    """
    try:
        
        rss_processor=RSSProcessor()
        feeds, total_count = await rss_processor.get_feeds_by_source(source, limit, skip)
        feeds = [feed.dict() for feed in feeds]
        return FeedResponse(
            items=feeds,
            total=total_count,
            limit=limit,
            skip=skip
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching feeds by source: {str(e)}")


@feeds_router.get("/search", response_model=FeedResponse)
async def search_feeds(
    q: Optional[str] = Query(None, description="Search query for title and content"),
    priority: Optional[str] = Query(None, description="Filter by priority level"),
    source: Optional[str] = Query(None, description="Filter by source"),
    limit: int = Query(10, ge=1, le=100, description="Number of items to return"),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Search and filter feeds by query, priority and/or source
    Empty or whitespace-only parameters are ignored
    """
    try:
        # Clean and validate query parameter
        clean_query = None
        if q and q.strip():
            clean_query = q.strip()
        
        # Clean and validate priority parameter
        clean_priority = None
        if priority and priority.strip():
            clean_priority = priority.strip()
            valid_priorities = ["Low", "Medium", "High", "Information"]
            if clean_priority not in valid_priorities:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid priority. Must be one of: {', '.join(valid_priorities)}"
                )
        
        # Clean and validate source parameter
        clean_source = None
        if source and source.strip():
            clean_source = source.strip()
        
        rss_processor = RSSProcessor()
        feeds, total_count = await rss_processor.search_feeds(
            query=clean_query,
            priority=clean_priority,
            source=clean_source,
            limit=limit,
            skip=skip
        )
        feeds = [feed.dict() for feed in feeds]
        
        return FeedResponse(
            items=feeds,
            total=total_count,
            limit=limit,
            skip=skip,
            filters={
                "query": clean_query,
                "priority": clean_priority,
                "source": clean_source
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching feeds: {str(e)}")

