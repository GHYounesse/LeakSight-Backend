from fastapi import APIRouter, Query, HTTPException, Depends
from typing import Optional
from app.dependencies import logger
from app.models.feeds import *
from app.api.auth import get_current_active_user
from app.models.auth import UserInDB
from app.crud.rss_processor import RSSProcessor


# Create the router
feeds_router = APIRouter(prefix="/api/v1/feeds", tags=["Feeds Management"])



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

