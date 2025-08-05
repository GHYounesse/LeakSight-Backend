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
        
from fastapi import FastAPI, HTTPException
from typing import List, Dict, Any, Optional
from datetime import datetime, date
from collections import defaultdict, Counter
import json
import redis
import hashlib
from contextlib import asynccontextmanager

OTX_CACHE_EXPIRATION = 4 * 24 * 60 * 60  # 4 days in seconds


OTX_API_KEY = os.getenv("ALIEN_VAULT_KEY")
async def fetch_otx_pulses() -> List[Dict[str, Any]]:

    if not OTX_API_KEY:
        raise HTTPException(status_code=500, detail="OTX API key not configured")

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }
    url = "https://otx.alienvault.com/api/v1/search/pulses?limit=100&page=1&sort=-modified"
    # In production, you would use httpx or requests:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            pulses = response.json().get("results", [])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch OTX data: {str(e)}")

    return pulses



# async def fetch_otx_pulses(max_pages: int = 5, delay: float = 2.0) -> List[Dict[str, Any]]:
#     """
#     Fetch OTX pulses with pagination and delay between requests.
    
#     :param max_pages: Number of pages to fetch (default is 5 = 500 pulses)
#     :param delay: Delay in seconds between requests (default is 1.0 second)
#     """
#     if not OTX_API_KEY:
#         raise HTTPException(status_code=500, detail="OTX API key not configured")

#     headers = {
#         "X-OTX-API-KEY": OTX_API_KEY
#     }

#     all_pulses = []
#     timeout = httpx.Timeout(20.0, connect=10.0, read=20.0)
#     async with httpx.AsyncClient(timeout=timeout) as client:
#         for page in range(1, max_pages + 1):
#             url = f"https://otx.alienvault.com/api/v1/search/pulses?limit=100&page={page}&sort=-modified"
#             try:
#                 response = await client.get(url, headers=headers)
#                 response.raise_for_status()
#                 data = response.json()
#                 pulses = data.get("results", [])
#                 if not pulses:
#                     break  # Stop if no more data
#                 all_pulses.extend(pulses)
#                 # await asyncio.sleep(delay)  # Delay before next request
#             except httpx.HTTPStatusError as e:
#                 raise HTTPException(status_code=500, detail=f"HTTP error on page {page}: {e.response.status_code} - {e.response.text}")
#             except Exception as e:
#                 tb = traceback.format_exc()
#                 raise HTTPException(status_code=500, detail=f"Unexpected error on page {page}: {str(e)}\n{tb}")

#     return all_pulses
def get_otx_cache_key(endpoint: str, params: Optional[Dict] = None) -> str:
    """Generate a consistent cache key for the endpoint."""
    key_data = f"{endpoint}"
    if params:
        # Sort params for consistent key generation
        sorted_params = json.dumps(params, sort_keys=True)
        key_data += f":{sorted_params}"
    
    # Create a hash for cleaner keys
    return f"otx_cache:{hashlib.md5(key_data.encode()).hexdigest()}"

def get_otx_from_cache(cache_key: str) -> Optional[Dict]:
    """Retrieve data from Redis cache."""
    if not redis_client:
        return None
    
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except (redis.RedisError, json.JSONDecodeError) as e:
        print(f"Cache read error: {e}")
    
    return None

def set_otx_to_cache(cache_key: str, data: Dict, expiration: int = OTX_CACHE_EXPIRATION) -> bool:
    """Store data in Redis cache with expiration."""
    if not redis_client:
        return False
    
    try:
        redis_client.setex(
            cache_key,
            expiration,
            json.dumps(data, default=str)  # default=str handles datetime serialization
        )
        return True
    except (redis.RedisError, json.JSONEncodeError) as e:
        print(f"Cache write error: {e}")
        return False

def invalidate_cache_pattern(pattern: str) -> int:
    """Invalidate cache entries matching a pattern."""
    if not redis_client:
        return 0
    
    try:
        keys = redis_client.keys(pattern)
        if keys:
            return redis_client.delete(*keys)
        return 0
    except redis.RedisError as e:
        print(f"Cache invalidation error: {e}")
        return 0
    

def process_trending_timeline(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process pulses to create trending attack campaigns timeline."""
    date_counts = defaultdict(int)
    
    for pulse in pulses:
        # Parse the created date and extract just the date part
        created_datetime = datetime.fromisoformat(pulse["created"].replace("Z", "+00:00"))
        date_str = created_datetime.date().isoformat()
        date_counts[date_str] += 1
    
    # Sort by date ascending
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
    
    # Get top 10 malware families
    top_malware = [
        {"malware_family": family, "count": count}
        for family, count in malware_counts.most_common(10)
    ]
    
    return top_malware

def process_popularity_leaderboard(pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process pulses to create popularity leaderboard by subscriber count."""
    # Sort by subscriber_count descending and take top 10
    sorted_pulses = sorted(
        pulses, 
        key=lambda x: x.get("subscriber_count", 0), 
        reverse=True
    )[:10]
    
    leaderboard = [
        {
            "pulse_name": pulse.get("name", "Unknown"),
            "subscriber_count": pulse.get("subscriber_count", 0),
            "export_count": pulse.get("export_count", 0)
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

@dashboard_router.get("/otx/pulse-insights")
async def get_pulse_insights():
    """
    Fetch and process AlienVault OTX pulse data to return structured insights.
    Results are cached in Redis for 4 days to improve performance.
    
    Returns:
        dict: JSON response containing trending timeline, top malware families,
              popularity leaderboard, and indicator type distribution.
    """
    # Generate cache key
    cache_key = get_otx_cache_key("pulse_insights")
    
    # Try to get from cache first
    cached_result = get_otx_from_cache(cache_key)
    if cached_result:
        logger.info(f"OTX Cache hit for key: {cache_key}")
        # Add cache metadata
        cached_result["_cache_info"] = {
            "cached": True,
            "cache_key": cache_key,
            "retrieved_at": datetime.utcnow().isoformat()
        }
        return cached_result
    
    try:
        
        pulses = await fetch_otx_pulses()
        
        if not pulses:
            raise HTTPException(status_code=404, detail="No pulse data available")
        
        # Process the different datasets
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
                "cache_duration_hours": OTX_CACHE_EXPIRATION // 3600
            }
        }
        
        # Cache the response
        cache_success = set_otx_to_cache(cache_key, response)
        
        # Add cache info to response
        response["_cache_info"] = {
            "cached": False,
            "cache_stored": cache_success,
            "cache_key": cache_key if cache_success else None,
            "will_expire_at": (
                datetime.utcnow().timestamp() + OTX_CACHE_EXPIRATION
            ) if cache_success else None
        }
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing pulse data: {str(e)}")

# Cache management endpoints
@dashboard_router.delete("/otx/cache/clear")
async def clear_pulse_cache():
    """Clear all OTX pulse-related cache entries."""
    try:
        cleared_count = invalidate_cache_pattern("otx_cache:*")
        return {
            "message": f"Cleared {cleared_count} cache entries",
            "cleared_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error clearing cache: {str(e)}")

@dashboard_router.get("/otx/cache/status")
async def get_cache_status():
    """Get Redis cache connection status and stats."""
    if not redis_client:
        return {
            "connected": False,
            "message": "Redis client not available"
        }
    
    try:
        info = redis_client.info()
        cache_keys = redis_client.keys("otx_cache:*")
        
        return {
            "connected": True,
            "redis_version": info.get("redis_version"),
            "used_memory_human": info.get("used_memory_human"),
            "connected_clients": info.get("connected_clients"),
            "cache_entries": len(cache_keys),
            "cache_keys": cache_keys[:10] if cache_keys else [],  # Show first 10 keys
            "cache_expiration_hours": OTX_CACHE_EXPIRATION // 3600
        }
    except Exception as e:
        return {
            "connected": False,
            "error": str(e)
        }

# # Additional endpoint to demonstrate the data structure
# @app.get("/api/otx/sample-pulse")
# async def get_sample_pulse():
#     """Return a sample pulse for reference."""
#     return SAMPLE_PULSES[0] if SAMPLE_PULSES else {}





# # Constants
# CACHE_TTL = 172800  # 2 days in seconds
# SHODAN_BASE_URL = "https://api.shodan.io"



# async def get_shodan_api_key() -> str:
#     """Get Shodan API key from environment variables."""
#     api_key = os.getenv("SHODAN_AUTH_KEY")
#     if not api_key:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="SHODAN_API_KEY environment variable not set"
#         )
#     return api_key




# async def make_shodan_request(endpoint: str, api_key: str) -> Dict[str, Any]:
#     """Make async HTTP request to Shodan API."""
#     url = f"{SHODAN_BASE_URL}/{endpoint}"
#     params = {"key": api_key}
    
#     try:
#         async with httpx.AsyncClient(timeout=30.0) as client:
#             response = await client.get(url, params=params)
            
#             if response.status_code == 401:
#                 raise HTTPException(
#                     status_code=status.HTTP_401_UNAUTHORIZED,
#                     detail="Invalid Shodan API key"
#                 )
#             elif response.status_code == 403:
#                 raise HTTPException(
#                     status_code=status.HTTP_403_FORBIDDEN,
#                     detail="Shodan API access forbidden - check your plan limits"
#                 )
#             elif response.status_code == 429:
#                 raise HTTPException(
#                     status_code=status.HTTP_429_TOO_MANY_REQUESTS,
#                     detail="Shodan API rate limit exceeded"
#                 )
#             elif response.status_code != 200:
#                 raise HTTPException(
#                     status_code=status.HTTP_502_BAD_GATEWAY,
#                     detail=f"Shodan API error: {response.status_code}"
#                 )
            
#             return response.json()
            
#     except httpx.TimeoutException:
#         raise HTTPException(
#             status_code=status.HTTP_504_GATEWAY_TIMEOUT,
#             detail="Shodan API request timeout"
#         )
#     except httpx.RequestError as e:
#         logger.error(f"Shodan API request error: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_502_BAD_GATEWAY,
#             detail="Failed to connect to Shodan API"
#         )

# def generate_shodan_cache_key(endpoint: str) -> str:
#     """Generate a unique cache key based on request parameters"""
#     key_data = f"shodan:{endpoint}"
#     return hashlib.md5(key_data.encode()).hexdigest()
# @dashboard_router.get("/top-ports")
# async def get_top_ports():
#     """
#     Get the top open ports globally from Shodan.
#     Returns cached data if available, otherwise fetches fresh data.
#     """
#     cache_key = generate_shodan_cache_key("top_ports")
    
#     try:
#         redis = redis_client
#         api_key = await get_shodan_api_key()
        
#         # Try to get cached data
#         cached_data = get_cached_data(cache_key)
#         if cached_data:
#             return JSONResponse(content=cached_data)
        
#         # Fetch fresh data from Shodan
#         logger.info("Fetching top ports from Shodan API")
#         raw_data = await make_shodan_request("shodan/ports", api_key)
        
#         # Process and structure the response
#         response_data = {
#             "endpoint": "top-ports",
#             "cached": False,
#             "data": raw_data,
#             "total_ports": len(raw_data) if isinstance(raw_data, list) else None
#         }
        
#         # Cache the processed data
#         await set_cached_data(redis, cache_key, response_data)
        
#         return JSONResponse(content=response_data)
        
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Unexpected error in get_top_ports: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Internal server error"
#         )


# @dashboard_router.get("/top-services")
# async def get_top_services():
#     """
#     Get the top exposed services globally from Shodan.
#     Returns cached data if available, otherwise fetches fresh data.
#     """
#     cache_key = generate_shodan_cache_key("top_services")

#     try:
#         redis = redis_client
#         api_key = await get_shodan_api_key()
        
#         # Try to get cached data
#         cached_data = get_cached_data(cache_key)
#         if cached_data:
#             return JSONResponse(content=cached_data)
        
#         # Fetch fresh data from Shodan
#         logger.info("Fetching top services from Shodan API")
#         raw_data = await make_shodan_request("shodan/services", api_key)
        
#         # Process and structure the response
#         response_data = {
#             "endpoint": "top-services",
#             "cached": False,
#             "data": raw_data,
#             "total_services": len(raw_data) if isinstance(raw_data, dict) else None
#         }
        
#         # Cache the processed data
#         await set_cached_data(redis, cache_key, response_data)
        
#         return JSONResponse(content=response_data)
        
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Unexpected error in get_top_services: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Internal server error"
#         )


# @dashboard_router.get("/top-countries")
# async def get_top_countries():
#     """
#     Get the top countries by number of exposed hosts from Shodan.
#     Returns cached data if available, otherwise fetches fresh data.
#     """
#     cache_key = generate_shodan_cache_key("top_countries")

#     try:
#         redis = redis_client
#         api_key = await get_shodan_api_key()
        
#         # Try to get cached data
#         cached_data = get_cached_data(cache_key)
#         if cached_data:
#             return JSONResponse(content=cached_data)
        
#         # Fetch fresh data from Shodan
#         logger.info("Fetching top countries from Shodan API")
#         raw_data = await make_shodan_request("shodan/host-search", api_key)
        
#         # For countries, we need to use a different approach since Shodan doesn't have a direct endpoint
#         # We'll use the query endpoint with facets to get country statistics
#         country_data = await make_shodan_request(
#             "shodan/host/search?query=*&facets=country:50", 
#             api_key
#         )
        
#         # Extract country facet data
#         countries = []
#         if "facets" in country_data and "country" in country_data["facets"]:
#             for item in country_data["facets"]["country"]:
#                 countries.append({
#                     "country_code": item["value"],
#                     "host_count": item["count"]
#                 })
        
#         # Process and structure the response
#         response_data = {
#             "endpoint": "top-countries",
#             "cached": False,
#             "data": {
#                 "countries": countries,
#                 "total_results": country_data.get("total", 0)
#             },
#             "total_countries": len(countries)
#         }
        
#         # Cache the processed data
#         await set_cached_data(redis, cache_key, response_data)
        
#         return JSONResponse(content=response_data)
        
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Unexpected error in get_top_countries: {e}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Internal server error"
#         )



