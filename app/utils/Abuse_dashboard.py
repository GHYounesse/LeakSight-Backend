import json
import hashlib
from datetime import datetime, timedelta
import httpx
import redis
from fastapi import HTTPException
from pydantic import BaseModel

from app.config import settings
from app.dependencies import logger
#from app.main import redis_client
from typing import List, Optional

import json



# Configuration
ABUSEIPDB_API_KEY = settings.ABUSEIPDB_AUTH_KEY
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

CACHE_TTL_HOURS = 8 # Cache for 8 hours (3 API calls per day)


try:
    redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
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