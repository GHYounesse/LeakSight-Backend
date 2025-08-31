# import json
# import hashlib
from datetime import datetime, timedelta
# import requests
import httpx
# import redis
from fastapi import APIRouter, Query, HTTPException
# from pydantic import BaseModel
import asyncio
# from app.config import settings
from app.dependencies import logger
#from app.main import redis_client
# from typing import List, Dict, Any, Optional
# from collections import defaultdict, Counter
# from app.crud.ioc_crud import IOCCRUD
from dataclasses import dataclass
import json
from app.utils.Abuse_dashboard import *
from app.utils.OTX_dashboard import *

dashboard_router = APIRouter(prefix="/api/v1", tags=["Dashboard Resources"])





@dashboard_router.get("/abuse-blacklist", response_model=BlacklistResponse)
async def get_abuse_blacklist(
    max_age_in_days: int = Query(30, ge=1, le=365, description="Maximum age of reports in days"),
    confidence_minimum: int = Query(75, ge=25, le=100, description="Minimum confidence percentage")
):
    """
    Get abuse blacklist data with Redis caching to limit API calls to ~3 times per day
    """
    cache_key = generate_cache_key(max_age_in_days, confidence_minimum)
    
    # Try to get data from cache first
    cached_data = get_cached_data(cache_key)
    if cached_data:
        # Transform cached data to match frontend interface
        threat_data = []
        for item in cached_data.get("data", []):
            threat_item = ThreatData(
                ipAddress=item.get("ipAddress", ""),
                countryCode=item.get("countryCode", ""),
                abuseConfidenceScore=int(item.get("abuseConfidenceScore", 0)),
                lastReportedAt=item.get("lastReportedAt", "")
            )
            threat_data.append(threat_item)
        
        return BlacklistResponse(
            data=threat_data,
            success=True,
            message=f"Retrieved {len(threat_data)} threat records from cache",
            cached=True
        )
    
    # Cache miss - fetch from API
    try:
        logger.info("Cache miss - fetching fresh data from AbuseIPDB API")
        api_data = await fetch_from_abuseipdb(max_age_in_days, confidence_minimum)
        
        # Cache the fresh data
        set_cached_data(cache_key, api_data)
        
        # Transform data to match frontend interface
        threat_data = []
        for item in api_data.get("data", []):
            threat_item = ThreatData(
                ipAddress=item.get("ipAddress", ""),
                countryCode=item.get("countryCode", ""),
                abuseConfidenceScore=int(item.get("abuseConfidenceScore", 0)),
                lastReportedAt=item.get("lastReportedAt", "")
            )
            threat_data.append(threat_item)
        
        logger.info(f"Successfully fetched and cached {len(threat_data)} threat records")
        
        return BlacklistResponse(
            data=threat_data,
            success=True,
            message=f"Retrieved {len(threat_data)} fresh threat records",
            cached=False
        )
        
    except httpx.TimeoutException:
        logger.error("Timeout while connecting to AbuseIPDB API")
        raise HTTPException(
            status_code=504,
            detail="Timeout while fetching data from AbuseIPDB"
        )
    except httpx.RequestError as e:
        logger.error(f"Request error: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail="Unable to connect to AbuseIPDB API"
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while processing request"
        )

# @dashboard_router.delete("/abuse-blacklist/cache")
# async def clear_cache():
#     """
#     Clear all cached AbuseIPDB data (useful for debugging or forced refresh)
#     """
#     if not redis_client:
#         raise HTTPException(
#             status_code=503,
#             detail="Redis not available"
#         )
    
#     try:
#         # Find all cache keys with our pattern
#         pattern = "abuseipdb:blacklist:*"
#         keys = redis_client.keys(pattern)
        
#         if keys:
#             deleted_count = redis_client.delete(*keys)
#             logger.info(f"Cleared {deleted_count} cache entries")
#             return {"success": True, "message": f"Cleared {deleted_count} cache entries"}
#         else:
#             return {"success": True, "message": "No cache entries found to clear"}
            
#     except Exception as e:
#         logger.error(f"Error clearing cache: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail="Error clearing cache"
#         )
        


async def cache_refresh_scheduler():
    """Background scheduler for cache refresh."""
    logger.info("Cache refresh scheduler started")
    
    # Initial cache population
    await refresh_otx_cache()
    
    while True:
        try:
            await asyncio.sleep(CACHE_REFRESH_INTERVAL)
            await refresh_otx_cache()
        except Exception as e:
            logger.error(f"Error in cache refresh scheduler: {e}")
            await asyncio.sleep(60)  # Wait 1 minute before retrying


# API Endpoints
@dashboard_router.get("/otx/pulse-insights")
async def get_pulse_insights():
    """
    Serve cached OTX pulse insights. Always returns immediately from cache.
    If cache is empty, returns a message indicating data is being fetched.
    
    Returns:
        dict: JSON response containing pulse insights or loading message
    """
    cache_key = get_otx_cache_key("pulse_insights")
    
    # Always try cache first
    cached_result = get_otx_from_cache(cache_key)
    
    if cached_result:
        logger.info("Serving data from cache")
        cached_result["_cache_info"] = {
            "served_from_cache": True,
            "served_at": datetime.utcnow().isoformat()
        }
        return cached_result
    
    # If no cache, return loading message but don't wait
    logger.info("No cached data available, returning loading message")
    return {
        "message": "Threat intelligence data is being fetched and processed. Please try again in a few moments.",
        "status": "loading",
        "estimated_wait_seconds": 30,
        "_cache_info": {
            "served_from_cache": False,
            "cache_empty": True,
            "background_fetch_in_progress": True
        }
    }

# @app.post("/api/otx/refresh-cache")
# async def trigger_cache_refresh(background_tasks: BackgroundTasks):
#     """
#     Manually trigger a cache refresh (useful for testing or immediate updates).
    
#     Returns:
#         dict: Status message
#     """
#     background_tasks.add_task(refresh_otx_cache)
    
#     return {
#         "message": "Cache refresh triggered",
#         "status": "initiated",
#         "timestamp": datetime.utcnow().isoformat()
#     }

# @app.get("/api/otx/cache-status")
# async def get_cache_status():
#     """
#     Get information about the current cache status.
    
#     Returns:
#         dict: Cache status information
#     """
#     cache_key = get_otx_cache_key("pulse_insights")
    
#     # Check if main cache exists
#     cached_data = get_otx_from_cache(cache_key)
#     has_cache = cached_data is not None
    
#     # Get cache metadata
#     metadata = get_otx_from_cache(f"{cache_key}:metadata")
    
#     # Get TTL from Redis
#     ttl = None
#     if redis_client and has_cache:
#         try:
#             ttl = redis_client.ttl(cache_key)
#         except redis.RedisError:
#             pass
    
#     return {
#         "cache_exists": has_cache,
#         "cache_key": cache_key,
#         "ttl_seconds": ttl,
#         "metadata": metadata,
#         "redis_connected": redis_client is not None,
#         "checked_at": datetime.utcnow().isoformat()
#     }



