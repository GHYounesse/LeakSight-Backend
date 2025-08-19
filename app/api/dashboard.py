import os
import json
import hashlib
from datetime import datetime, timedelta
import traceback
from typing import List, Optional
import httpx
import redis
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
import logging
import os
from typing import Dict, Any, Optional
import asyncio
from contextlib import asynccontextmanager
import json
import httpx

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
load_dotenv()
logger = logging.getLogger(__name__)

dashboard_router = APIRouter(prefix="/api/v1", tags=["Dashboard Resources"])

# Configuration
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_AUTH_KEY", "YOUR_API_KEY_HERE")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "8"))  # Cache for 8 hours (3 API calls per day)

# Initialize Redis client
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    # Test connection
    redis_client.ping()
    logger.info("Redis connection established successfully")
except Exception as e:
    logger.error(f"Failed to connect to Redis: {str(e)}")
    redis_client = None

if ABUSEIPDB_API_KEY == "YOUR_API_KEY_HERE":
    logger.warning("AbuseIPDB API key not set. Please set ABUSEIPDB_API_KEY environment variable.")

class ThreatData(BaseModel):
    ipAddress: str
    countryCode: str
    abuseConfidenceScore: int
    lastReportedAt: str

class BlacklistResponse(BaseModel):
    data: List[ThreatData]
    success: bool
    message: Optional[str] = None
    cached: Optional[bool] = False  # Indicate if data came from cache

def generate_cache_key(max_age_in_days: int, confidence_minimum: int) -> str:
    """Generate a unique cache key based on request parameters"""
    key_data = f"abuseipdb:blacklist:{max_age_in_days}:{confidence_minimum}"
    return hashlib.md5(key_data.encode()).hexdigest()

def get_cached_data(cache_key: str) -> Optional[dict]:
    """Retrieve cached data from Redis"""
    if not redis_client:
        return None
    
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            data = json.loads(cached_data)
            # Check if cache includes timestamp
            if 'timestamp' in data:
                cached_time = datetime.fromisoformat(data['timestamp'])
                if datetime.now() - cached_time < timedelta(hours=CACHE_TTL_HOURS):
                    logger.info(f"Cache hit for key: {cache_key}")
                    return data['data']
                else:
                    # Cache expired, delete it
                    redis_client.delete(cache_key)
                    logger.info(f"Cache expired for key: {cache_key}")
            else:
                # Old cache format without timestamp, delete it
                redis_client.delete(cache_key)
        return None
    except Exception as e:
        logger.error(f"Error retrieving from cache: {str(e)}")
        return None

def set_cached_data(cache_key: str, data: dict) -> bool:
    """Store data in Redis cache with timestamp"""
    if not redis_client:
        return False
    
    try:
        cache_data = {
            'data': data,
            'timestamp': datetime.now().isoformat()
        }
        redis_client.setex(
            cache_key, 
            timedelta(hours=CACHE_TTL_HOURS + 1),  # Add 1 hour buffer
            json.dumps(cache_data)
        )
        logger.info(f"Data cached successfully for key: {cache_key}")
        return True
    except Exception as e:
        logger.error(f"Error caching data: {str(e)}")
        return False

async def fetch_from_abuseipdb(max_age_in_days: int, confidence_minimum: int) -> dict:
    """Fetch fresh data from AbuseIPDB API"""
    if ABUSEIPDB_API_KEY == "YOUR_API_KEY_HERE":
        raise HTTPException(
            status_code=500, 
            detail="AbuseIPDB API key not configured"
        )
    
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    
    params = {
        "maxAgeInDays": max_age_in_days,
        "confidenceMinimum": confidence_minimum
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{ABUSEIPDB_BASE_URL}/blacklist",
            headers=headers,
            params=params
        )
        
        if response.status_code == 200:
            data = response.json()
            logger.info(f"Successfully fetched data from AbuseIPDB API")
            return data
        elif response.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail="Invalid AbuseIPDB API key"
            )
        elif response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="AbuseIPDB API rate limit exceeded"
            )
        else:
            logger.error(f"AbuseIPDB API error: {response.status_code} - {response.text}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"AbuseIPDB API error: {response.text}"
            )

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

@dashboard_router.delete("/abuse-blacklist/cache")
async def clear_cache():
    """
    Clear all cached AbuseIPDB data (useful for debugging or forced refresh)
    """
    if not redis_client:
        raise HTTPException(
            status_code=503,
            detail="Redis not available"
        )
    
    try:
        # Find all cache keys with our pattern
        pattern = "abuseipdb:blacklist:*"
        keys = redis_client.keys(pattern)
        
        if keys:
            deleted_count = redis_client.delete(*keys)
            logger.info(f"Cleared {deleted_count} cache entries")
            return {"success": True, "message": f"Cleared {deleted_count} cache entries"}
        else:
            return {"success": True, "message": "No cache entries found to clear"}
            
    except Exception as e:
        logger.error(f"Error clearing cache: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error clearing cache"
        )
        
# from fastapi import FastAPI, HTTPException
# from typing import List, Dict, Any, Optional
# from datetime import datetime, date
# from collections import defaultdict, Counter
# import json
# import redis
# import hashlib
# from contextlib import asynccontextmanager

# OTX_CACHE_EXPIRATION = 4 * 24 * 60 * 60  # 4 days in seconds


# OTX_API_KEY = os.getenv("ALIEN_VAULT_KEY")
# async def fetch_otx_pulses() -> List[Dict[str, Any]]:
#     if not OTX_API_KEY:
#         raise HTTPException(status_code=500, detail="OTX API key not configured")

#     headers = {"X-OTX-API-KEY": OTX_API_KEY}
#     url = "https://otx.alienvault.com/api/v1/search/pulses?limit=100&page=1&sort=-modified"

#     try:
#         async with httpx.AsyncClient() as client:
#             response = await client.get(url, headers=headers)
#             print("Status code:", response.status_code)
#             print("Response text:", response.text)
#             response.raise_for_status()
#             data = await response.json()
#             pulses = data.get("results", [])
#     except httpx.HTTPStatusError as e:
#         raise HTTPException(status_code=e.response.status_code, detail=f"HTTP error: {e.response.text}")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to fetch OTX data: {str(e)}")

#     return pulses


# def get_otx_cache_key(endpoint: str, params: Optional[Dict] = None) -> str:
#     """Generate a consistent cache key for the endpoint."""
#     key_data = f"{endpoint}"
#     if params:
#         # Sort params for consistent key generation
#         sorted_params = json.dumps(params, sort_keys=True)
#         key_data += f":{sorted_params}"
    
#     # Create a hash for cleaner keys
#     return f"otx_cache:{hashlib.md5(key_data.encode()).hexdigest()}"

# def get_otx_from_cache(cache_key: str) -> Optional[Dict]:
#     """Retrieve data from Redis cache."""
#     if not redis_client:
#         return None
    
#     try:
#         cached_data = redis_client.get(cache_key)
#         if cached_data:
#             return json.loads(cached_data)
#     except (redis.RedisError, json.JSONDecodeError) as e:
#         print(f"Cache read error: {e}")
    
#     return None

# def set_otx_to_cache(cache_key: str, data: Dict, expiration: int = OTX_CACHE_EXPIRATION) -> bool:
#     """Store data in Redis cache with expiration."""
#     if not redis_client:
#         return False
    
#     try:
#         redis_client.setex(
#             cache_key,
#             expiration,
#             json.dumps(data, default=str)  # default=str handles datetime serialization
#         )
#         return True
#     except (redis.RedisError, json.JSONEncodeError) as e:
#         print(f"Cache write error: {e}")
#         return False

# def invalidate_cache_pattern(pattern: str) -> int:
#     """Invalidate cache entries matching a pattern."""
#     if not redis_client:
#         return 0
    
#     try:
#         keys = redis_client.keys(pattern)
#         if keys:
#             return redis_client.delete(*keys)
#         return 0
#     except redis.RedisError as e:
#         print(f"Cache invalidation error: {e}")
#         return 0
    

# def process_trending_timeline(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#     """Process pulses to create trending attack campaigns timeline."""
#     date_counts = defaultdict(int)
    
#     for pulse in pulses:
#         # Parse the created date and extract just the date part
#         created_datetime = datetime.fromisoformat(pulse["created"].replace("Z", "+00:00"))
#         date_str = created_datetime.date().isoformat()
#         date_counts[date_str] += 1
    
#     # Sort by date ascending
#     timeline = [
#         {"date": date_str, "count": count}
#         for date_str, count in sorted(date_counts.items())
#     ]
    
#     return timeline

# def process_top_malware_families(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#     """Process pulses to get top malware families by pulse count."""
#     malware_counts = Counter()
    
#     for pulse in pulses:
#         for malware_family in pulse.get("malware_families", []):
#             family_name = malware_family.get("display_name")
#             if family_name:
#                 malware_counts[family_name] += 1
    
#     # Get top 10 malware families
#     top_malware = [
#         {"malware_family": family, "count": count}
#         for family, count in malware_counts.most_common(10)
#     ]
    
#     return top_malware

# def process_popularity_leaderboard(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#     """Process pulses to create popularity leaderboard by subscriber count."""
#     # Sort by subscriber_count descending and take top 10
#     sorted_pulses = sorted(
#         pulses, 
#         key=lambda x: x.get("subscriber_count", 0), 
#         reverse=True
#     )[:10]
    
#     leaderboard = [
#         {
#             "pulse_name": pulse.get("name", "Unknown"),
#             "subscriber_count": pulse.get("subscriber_count", 0),
#             "export_count": pulse.get("export_count", 0)
#         }
#         for pulse in sorted_pulses
#     ]
    
#     return leaderboard

# def process_indicator_type_distribution(pulses: List[Dict[str, Any]]) -> Dict[str, int]:
#     """Process pulses to aggregate indicator type counts."""
#     total_indicators = defaultdict(int)
    
#     for pulse in pulses:
#         indicator_counts = pulse.get("indicator_type_counts", {})
#         for indicator_type, count in indicator_counts.items():
#             total_indicators[indicator_type] += count
    
#     return dict(total_indicators)

# @dashboard_router.get("/otx/pulse-insights")
# async def get_pulse_insights():
#     """
#     Fetch and process AlienVault OTX pulse data to return structured insights.
#     Results are cached in Redis for 4 days to improve performance.
    
#     Returns:
#         dict: JSON response containing trending timeline, top malware families,
#               popularity leaderboard, and indicator type distribution.
#     """
#     # Generate cache key
#     cache_key = get_otx_cache_key("pulse_insights")
    
#     # Try to get from cache first
#     cached_result = get_otx_from_cache(cache_key)
#     if cached_result:
#         logger.info(f"OTX Cache hit for key: {cache_key}")
#         # Add cache metadata
#         cached_result["_cache_info"] = {
#             "cached": True,
#             "cache_key": cache_key,
#             "retrieved_at": datetime.utcnow().isoformat()
#         }
#         return cached_result
    
#     try:
        
#         pulses = await fetch_otx_pulses()
        
#         if not pulses:
#             raise HTTPException(status_code=404, detail="No pulse data available")
        
#         # Process the different datasets
#         trending_timeline = process_trending_timeline(pulses)
#         top_malware_families = process_top_malware_families(pulses)
#         popularity_leaderboard = process_popularity_leaderboard(pulses)
#         indicator_type_distribution = process_indicator_type_distribution(pulses)
        
#         # Structure the response
#         response = {
#             "trendingTimeline": trending_timeline,
#             "topMalwareFamilies": top_malware_families,
#             "popularityLeaderboard": popularity_leaderboard,
#             "indicatorTypeDistribution": indicator_type_distribution,
#             "metadata": {
#                 "total_pulses": len(pulses),
#                 "processed_at": datetime.utcnow().isoformat(),
#                 "cache_duration_hours": OTX_CACHE_EXPIRATION // 3600
#             }
#         }
        
#         # Cache the response
#         cache_success = set_otx_to_cache(cache_key, response)
        
#         # Add cache info to response
#         response["_cache_info"] = {
#             "cached": False,
#             "cache_stored": cache_success,
#             "cache_key": cache_key if cache_success else None,
#             "will_expire_at": (
#                 datetime.utcnow().timestamp() + OTX_CACHE_EXPIRATION
#             ) if cache_success else None
#         }
        
#         return response
        
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error processing pulse data: {str(e)}")

# # Cache management endpoints
# @dashboard_router.delete("/otx/cache/clear")
# async def clear_pulse_cache():
#     """Clear all OTX pulse-related cache entries."""
#     try:
#         cleared_count = invalidate_cache_pattern("otx_cache:*")
#         return {
#             "message": f"Cleared {cleared_count} cache entries",
#             "cleared_at": datetime.utcnow().isoformat()
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error clearing cache: {str(e)}")

# @dashboard_router.get("/otx/cache/status")
# async def get_cache_status():
#     """Get Redis cache connection status and stats."""
#     if not redis_client:
#         return {
#             "connected": False,
#             "message": "Redis client not available"
#         }
    
#     try:
#         info = redis_client.info()
#         cache_keys = redis_client.keys("otx_cache:*")
        
#         return {
#             "connected": True,
#             "redis_version": info.get("redis_version"),
#             "used_memory_human": info.get("used_memory_human"),
#             "connected_clients": info.get("connected_clients"),
#             "cache_entries": len(cache_keys),
#             "cache_keys": cache_keys[:10] if cache_keys else [],  # Show first 10 keys
#             "cache_expiration_hours": OTX_CACHE_EXPIRATION // 3600
#         }
#     except Exception as e:
#         return {
#             "connected": False,
#             "error": str(e)
#         }

from fastapi import FastAPI, HTTPException, BackgroundTasks
from typing import List, Dict, Any, Optional
from datetime import datetime, date, timedelta
from collections import defaultdict, Counter
import json
import redis
import hashlib
import asyncio
import httpx
import os
import logging
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
OTX_CACHE_EXPIRATION = 4 * 24 * 60 * 60  # 4 days in seconds
OTX_API_KEY = os.getenv("ALIEN_VAULT_KEY")

MAX_PAGES = 6  # Fetch up to 6 pages (50 * 6 = 300 pulses)
PULSES_PER_PAGE = 50
CACHE_REFRESH_INTERVAL = 6 * 60 * 60  # Refresh cache every 6 hours





    


async def fetch_single_page_otx_pulses(page: int = 1, limit: int = PULSES_PER_PAGE) -> Dict[str, Any]:
    """
    Fetch a single page of OTX pulses.
    
    Args:
        page: Page number (1-based)
        limit: Number of pulses per page
    
    Returns:
        dict: Raw API response containing pulses and metadata
    """
    if not OTX_API_KEY:
        raise ValueError("OTX API key not configured")

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"https://otx.alienvault.com/api/v1/search/pulses?limit={limit}&page={page}&sort=-modified"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            logger.info(f"OTX API Page {page} - Status: {response.status_code}")
            response.raise_for_status()
            data = response.json()
            
            return {
                "results": data.get("results", []),
                "count": data.get("count", 0),
                "next": data.get("next"),
                "page": page
            }
    except httpx.TimeoutException:
        logger.error(f"Timeout fetching OTX page {page}")
        raise
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error fetching OTX page {page}: {e.response.status_code}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error fetching OTX page {page}: {str(e)}")
        raise

async def fetch_multiple_pages_otx_pulses(max_pages: int = MAX_PAGES) -> List[Dict[str, Any]]:
    """
    Fetch multiple pages of OTX pulses asynchronously.
    
    Args:
        max_pages: Maximum number of pages to fetch
    
    Returns:
        list: Combined list of all pulses from all pages
    """
    logger.info(f"Starting to fetch {max_pages} pages of OTX pulses")
    
    # Create tasks for all pages
    tasks = []
    for page in range(1, max_pages + 1):
        task = fetch_single_page_otx_pulses(page, PULSES_PER_PAGE)
        tasks.append(task)
    
    # Execute all tasks concurrently
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_pulses = []
        successful_pages = 0
        
        for i, result in enumerate(results, 1):
            if isinstance(result, Exception):
                logger.error(f"Failed to fetch page {i}: {result}")
                continue
            
            page_pulses = result.get("results", [])
            all_pulses.extend(page_pulses)
            successful_pages += 1
            logger.info(f"Successfully fetched page {i}: {len(page_pulses)} pulses")
        
        logger.info(f"Completed fetching {successful_pages}/{max_pages} pages, total pulses: {len(all_pulses)}")
        return all_pulses
        
    except Exception as e:
        logger.error(f"Error in concurrent fetch: {str(e)}")
        raise

def get_otx_cache_key(endpoint: str, params: Optional[Dict] = None) -> str:
    """Generate a consistent cache key for the endpoint."""
    key_data = f"otx:{endpoint}"
    if params:
        sorted_params = json.dumps(params, sort_keys=True)
        key_data += f":{sorted_params}"
    
    return f"cache:{hashlib.md5(key_data.encode()).hexdigest()}"

def get_otx_from_cache(cache_key: str) -> Optional[Dict]:
    """Retrieve data from Redis cache."""
    if not redis_client:
        return None
    
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except (redis.RedisError, json.JSONDecodeError) as e:
        logger.error(f"Cache read error: {e}")
    
    return None

def set_otx_to_cache(cache_key: str, data: Dict, expiration: int = OTX_CACHE_EXPIRATION) -> bool:
    """Store data in Redis cache with expiration."""
    if not redis_client:
        return False
    
    try:
        redis_client.setex(
            cache_key,
            expiration,
            json.dumps(data, default=str)
        )
        logger.info(f"Data cached with key: {cache_key}")
        return True
    except (redis.RedisError, json.JSONEncodeError) as e:
        logger.error(f"Cache write error: {e}")
        return False

def set_cache_metadata(key: str, metadata: Dict) -> bool:
    """Store cache metadata separately."""
    if not redis_client:
        return False
    
    try:
        metadata_key = f"{key}:metadata"
        redis_client.setex(
            metadata_key,
            OTX_CACHE_EXPIRATION,
            json.dumps(metadata, default=str)
        )
        return True
    except Exception as e:
        logger.error(f"Error storing cache metadata: {e}")
        return False

async def refresh_otx_cache() -> bool:
    """
    Background task to refresh OTX pulse cache.
    
    Returns:
        bool: True if cache was successfully refreshed
    """
    logger.info("Starting OTX cache refresh")
    
    try:
        # Fetch fresh data
        pulses = await fetch_multiple_pages_otx_pulses(MAX_PAGES)
        
        if not pulses:
            logger.warning("No pulses received during cache refresh")
            return False
        
        # Process the datasets
        trending_timeline = process_trending_timeline(pulses)
        top_malware_families = process_top_malware_families(pulses)
        popularity_leaderboard = process_popularity_leaderboard(pulses)
        indicator_type_distribution = process_indicator_type_distribution(pulses)
        
        # Structure the response
        response = {
            "trendingTimeline": trending_timeline,
            "topMalwareFamilies": top_malware_families,
            "popularityLeaderboard": popularity_leaderboard,
            "indicatorTypeDistribution": indicator_type_distribution,
            "metadata": {
                "total_pulses": len(pulses),
                "processed_at": datetime.utcnow().isoformat(),
                "cache_duration_hours": OTX_CACHE_EXPIRATION // 3600,
                "pages_fetched": min(MAX_PAGES, (len(pulses) // PULSES_PER_PAGE) + 1)
            }
        }
        
        # Cache the response
        cache_key = get_otx_cache_key("pulse_insights")
        cache_success = set_otx_to_cache(cache_key, response)
        
        # Store metadata about the cache refresh
        if cache_success:
            metadata = {
                "last_refresh": datetime.utcnow().isoformat(),
                "next_refresh": (datetime.utcnow() + timedelta(seconds=CACHE_REFRESH_INTERVAL)).isoformat(),
                "refresh_success": True,
                "pulses_count": len(pulses)
            }
            set_cache_metadata(cache_key, metadata)
        
        logger.info(f"Cache refresh completed successfully. Cached {len(pulses)} pulses")
        return cache_success
        
    except Exception as e:
        logger.error(f"Cache refresh failed: {str(e)}")
        # Store error metadata
        cache_key = get_otx_cache_key("pulse_insights")
        error_metadata = {
            "last_refresh_attempt": datetime.utcnow().isoformat(),
            "last_error": str(e),
            "refresh_success": False
        }
        set_cache_metadata(cache_key, error_metadata)
        return False

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

# Data processing functions (from your original code)
def process_trending_timeline(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process pulses to create trending attack campaigns timeline."""
    date_counts = defaultdict(int)
    
    for pulse in pulses:
        try:
            created_datetime = datetime.fromisoformat(pulse["created"].replace("Z", "+00:00"))
            date_str = created_datetime.date().isoformat()
            date_counts[date_str] += 1
        except (KeyError, ValueError) as e:
            logger.warning(f"Error processing pulse date: {e}")
            continue
    
    timeline = [
        {"date": date_str, "count": count}
        for date_str, count in sorted(date_counts.items())
    ]
    
    return timeline

def process_top_malware_families(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process pulses to get top malware families by pulse count."""
    malware_counts = Counter()
    
    for pulse in pulses:
        for malware_family in pulse.get("malware_families", []):
            family_name = malware_family.get("display_name")
            if family_name:
                malware_counts[family_name] += 1
    
    top_malware = [
        {"malware_family": family, "count": count}
        for family, count in malware_counts.most_common(10)
    ]
    
    return top_malware

def process_popularity_leaderboard(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process pulses to create popularity leaderboard by subscriber count."""
    sorted_pulses = sorted(
        pulses, 
        key=lambda x: x.get("subscriber_count", 0), 
        reverse=True
    )[:10]
    
    leaderboard = [
        {
            "pulse_name": pulse.get("name", "Unknown"),
            "subscriber_count": pulse.get("subscriber_count", 0),
            "export_count": pulse.get("export_count", 0),
            "created": pulse.get("created", "")
        }
        for pulse in sorted_pulses
    ]
    
    return leaderboard

def process_indicator_type_distribution(pulses: List[Dict[str, Any]]) -> Dict[str, int]:
    """Process pulses to aggregate indicator type counts."""
    total_indicators = defaultdict(int)
    
    for pulse in pulses:
        indicator_counts = pulse.get("indicator_type_counts", {})
        for indicator_type, count in indicator_counts.items():
            total_indicators[indicator_type] += count
    
    return dict(total_indicators)

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



