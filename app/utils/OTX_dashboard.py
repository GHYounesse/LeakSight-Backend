import json
import hashlib
from datetime import datetime, timedelta
import requests
import httpx
import redis
import aiohttp

import asyncio
from app.config import settings
from app.dependencies import logger
#from app.main import redis_client
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter
from app.crud.ioc_crud import IOCCRUD
from dataclasses import dataclass
import json
try:
    redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    # Test connection
    redis_client.ping()
    logger.info("Redis connection established successfully")
except Exception as e:
    logger.error(f"Failed to connect to Redis: {str(e)}")
    redis_client = None


OTX_API_KEY = settings.ALIEN_VAULT_KEY
# Constants
OTX_CACHE_EXPIRATION = 4 * 24 * 60 * 60  # 4 days in seconds
CACHE_REFRESH_INTERVAL = 6 * 60 * 60  # Refresh cache every 6 hours
MAX_PAGES = 1  # Fetch up to 10 pages (50 * 10 = 500 pulses)
PULSES_PER_PAGE = 50
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
    logger.info("Successfully created trending attack campaigns timeline")
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
    logger.info("Successfully created top malware families list")
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
    logger.info("Successfully created popularity leaderboard")
    return leaderboard

def process_indicator_type_distribution(pulses: List[Dict[str, Any]]) -> Dict[str, int]:
    """Process pulses to aggregate indicator type counts."""
    total_indicators = defaultdict(int)
    
    for pulse in pulses:
        indicator_counts = pulse.get("indicator_type_counts", {})
        for indicator_type, count in indicator_counts.items():
            total_indicators[indicator_type] += count
    logger.info("Successfully created indicator type distribution")
    return dict(total_indicators)





OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# def fetch_iocs_from_pulse(pulse_id: str):
#     """
#     Fetch indicators from an OTX pulse and normalize them.
    
#     Returns a list of objects:
#     {
#       "value": "indicator",
#       "type": "type",
#       "threat_level": "unknown",
#       "status": "is_active",
#       "description": "description",
#       "tags": ["example", "malware"],
#       "expiration_date": "expiration"
#     }
#     """
#     url = f"{OTX_BASE_URL}/pulses/{pulse_id}/indicators"
#     headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
#     response = requests.get(url, headers=headers)
#     response.raise_for_status()
    
#     results = response.json().get("results", [])
#     iocs = []

#     for r in results:
#         ioc_obj = IOC(
#             value=r.get("indicator"),
#             type=r.get("type"),
#             threat_level="unknown",
#             status="active" if r.get("is_active", 0) == 1 else "inactive",
#             description=r.get("description", ""),
#             tags=[],  # later you can fill with pulse tags
#             expiration_date=r.get("expiration")
#             )
#         iocs.append(ioc_obj)
    
#     return iocs

@dataclass
class IOC:
    value: str
    type: str
    threat_level: str
    status: str
    description: str
    tags: List[str]
    expiration_date: Optional[str]
from app.crud.ioc_crud import IOCCRUD
# async def saving_ioc(pulses: List[Dict[str, Any]]):
#     """Save Indicators of Compromise (IOCs) from pulses to the database."""
#     for pulse in pulses:
#             ioc_crud= IOCCRUD()
#             p=ioc_crud.save_pulse(pulse)
#             if p == None:
#                 continue

#             pulse_id= pulse.get("id")
#             iocs=fetch_iocs_from_pulse(pulse_id)
#             for ioc in iocs:
#                 ioc_crud= IOCCRUD()
#                 ioc =await ioc_crud.create_ioc_auto(ioc,pulse_id,"")
#                 if ioc is not None:
#                     print("IOC created successfully:", ioc)
#                 else:
#                     print("IOC already exists:", ioc)

            
        
#         # Save ioc_data to the database
#         # db.save_ioc(ioc_data)



async def saving_ioc(pulses: List[Dict[str, Any]]) -> bool:
    """
    Save Indicators of Compromise (IOCs) from pulses to the database.
    
    Returns:
        bool: True if all operations completed successfully
    """
    # Create single CRUD instance
    ioc_crud = IOCCRUD()
    total_errors = 0
    total_processed = 0
    
    try:
        # Process pulses in batches to avoid overwhelming the database
        batch_size = 10
        for i in range(0, len(pulses), batch_size):
            batch = pulses[i:i + batch_size]
            
            # Process batch
            batch_errors = await process_pulse_batch(ioc_crud, batch)
            total_errors += batch_errors
            total_processed += len(batch)
            
            # Small delay to prevent overwhelming the API/DB
            if i + batch_size < len(pulses):
                await asyncio.sleep(0.1)
        
        success_rate = (total_processed - total_errors) / total_processed if total_processed > 0 else 0
        logger.info(f"IOC processing completed. Success rate: {success_rate:.2%} ({total_processed - total_errors}/{total_processed})")
        
        # Consider it successful if more than 80% succeeded
        return success_rate > 0.8
        
    except Exception as e:
        logger.error(f"Critical error in IOC saving: {str(e)}", exc_info=True)
        return False


async def process_pulse_batch(ioc_crud: IOCCRUD, pulses: List[Dict[str, Any]]) -> int:
    """
    Process a batch of pulses and return the number of errors.
    
    Returns:
        int: Number of errors encountered
    """
    errors = 0
    
    for pulse in pulses:
        try:
            # Save pulse (improved to return proper status)
            pulse_result = await ioc_crud.save_pulse(pulse)
            if pulse_result.get("status") == "error":
                logger.warning(f"Failed to save pulse {pulse.get('id', 'unknown')}: {pulse_result.get('message')}")
                errors += 1
                continue
            
            # Skip if pulse already exists and we don't want to reprocess IOCs
            if pulse_result.get("status") == "exists":
                continue
                
            pulse_id = pulse.get("id")
            if not pulse_id:
                logger.warning("Pulse missing ID, skipping IOC processing")
                errors += 1
                continue
            
            # Fetch IOCs with error handling
            try:
                iocs = await fetch_iocs_from_pulse_async(pulse_id)
                if not iocs:
                    logger.debug(f"No IOCs found for pulse {pulse_id}")
                    continue
                
                # Batch create IOCs
                ioc_results = await ioc_crud.create_iocs_batch(iocs, pulse_id, "system")
                failed_iocs = sum(1 for result in ioc_results if result.get("status") == "error")
                
                if failed_iocs > 0:
                    logger.warning(f"Failed to create {failed_iocs}/{len(iocs)} IOCs for pulse {pulse_id}")
                    errors += 1
                    
            except Exception as ioc_error:
                logger.error(f"Error processing IOCs for pulse {pulse_id}: {str(ioc_error)}")
                errors += 1
                
        except Exception as pulse_error:
            logger.error(f"Error processing pulse {pulse.get('id', 'unknown')}: {str(pulse_error)}")
            errors += 1
    
    return errors


async def fetch_iocs_from_pulse_async(pulse_id: str) -> List[IOC]:
    """
    Fetch indicators from an OTX pulse asynchronously with proper error handling.
    
    Args:
        pulse_id: The OTX pulse ID
        
    Returns:
        List of IOC objects
        
    Raises:
        ValueError: If pulse_id is invalid
        aiohttp.ClientError: If API request fails
    """
    # Input validation
    if not pulse_id or not isinstance(pulse_id, str):
        raise ValueError("Invalid pulse_id provided")
    
    url = f"{OTX_BASE_URL}/pulses/{pulse_id}/indicators"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=30) as response:
                response.raise_for_status()
                data = await response.json()
                
        results = data.get("results", [])
        iocs = []

        for r in results:
            try:
                ioc_obj = IOC(
                    value=r.get("indicator", "").strip(),
                    type=r.get("type", "unknown"),
                    threat_level="unknown",
                    status="active" if r.get("is_active", 0) == 1 else "inactive",
                    description=r.get("description", "").strip(),
                    tags=r.get("tags", []),
                    expiration_date=r.get("expiration")
                )
                
                # Basic validation
                if ioc_obj.value:  # Only add IOCs with actual values
                    iocs.append(ioc_obj)
                    
            except Exception as e:
                logger.warning(f"Failed to create IOC object from data {r}: {str(e)}")
                continue
        logger.info(f"Successfully fetched IOCs for pulse {pulse_id}: {len(iocs)} found")
        return iocs
        
    except aiohttp.ClientTimeout:
        logger.error(f"Timeout fetching IOCs for pulse {pulse_id}")
        raise
    except aiohttp.ClientError as e:
        logger.error(f"HTTP error fetching IOCs for pulse {pulse_id}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error fetching IOCs for pulse {pulse_id}: {str(e)}")
        raise

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

# async def refresh_otx_cache() -> bool:
#     """
#     Background task to refresh OTX pulse cache.
    
#     Returns:
#         bool: True if cache was successfully refreshed
#     """
#     logger.info("Starting OTX cache refresh")
    
#     try:
#         # Fetch fresh data
#         pulses = await fetch_multiple_pages_otx_pulses(MAX_PAGES)
        
#         if not pulses:
#             logger.warning("No pulses received during cache refresh")
#             return False
        
#         # Process the datasets
#         trending_timeline = process_trending_timeline(pulses)
#         top_malware_families = process_top_malware_families(pulses)
#         popularity_leaderboard = process_popularity_leaderboard(pulses)
#         indicator_type_distribution = process_indicator_type_distribution(pulses)
#         # with open(f"output.json", "w", encoding="utf-8") as f:
#         #                 json.dump(pulses, f, indent=4, ensure_ascii=False)
        
#         await saving_ioc(pulses)

#         # Structure the response
#         response = {
#             "trendingTimeline": trending_timeline,
#             "topMalwareFamilies": top_malware_families,
#             "popularityLeaderboard": popularity_leaderboard,
#             "indicatorTypeDistribution": indicator_type_distribution,
#             "metadata": {
#                 "total_pulses": len(pulses),
#                 "processed_at": datetime.utcnow().isoformat(),
#                 "cache_duration_hours": OTX_CACHE_EXPIRATION // 3600,
#                 "pages_fetched": min(MAX_PAGES, (len(pulses) // PULSES_PER_PAGE) + 1)
#             }
#         }
        
#         # Cache the response
#         cache_key = get_otx_cache_key("pulse_insights")
#         cache_success = set_otx_to_cache(cache_key, response)
        
#         # Store metadata about the cache refresh
#         if cache_success:
#             metadata = {
#                 "last_refresh": datetime.utcnow().isoformat(),
#                 "next_refresh": (datetime.utcnow() + timedelta(seconds=CACHE_REFRESH_INTERVAL)).isoformat(),
#                 "refresh_success": True,
#                 "pulses_count": len(pulses)
#             }
#             set_cache_metadata(cache_key, metadata)
        
#         logger.info(f"Cache refresh completed successfully. Cached {len(pulses)} pulses")
#         return cache_success
        
#     except Exception as e:
#         logger.error(f"Cache refresh failed: {str(e)}")
#         # Store error metadata
#         cache_key = get_otx_cache_key("pulse_insights")
#         error_metadata = {
#             "last_refresh_attempt": datetime.utcnow().isoformat(),
#             "last_error": str(e),
#             "refresh_success": False
#         }
#         set_cache_metadata(cache_key, error_metadata)
#         return False



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
        
        # Save IOCs with improved error handling
        ioc_save_success = await saving_ioc(pulses)
        if not ioc_save_success:
            logger.warning("IOC saving completed with some errors")

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
                "pulses_count": len(pulses),
                "ioc_save_success": ioc_save_success
            }
            set_cache_metadata(cache_key, metadata)
        
        logger.info(f"Cache refresh completed successfully. Cached {len(pulses)} pulses")
        return cache_success
        
    except Exception as e:
        logger.error(f"Cache refresh failed: {str(e)}", exc_info=True)
        # Store error metadata
        cache_key = get_otx_cache_key("pulse_insights")
        error_metadata = {
            "last_refresh_attempt": datetime.utcnow().isoformat(),
            "last_error": str(e),
            "refresh_success": False
        }
        set_cache_metadata(cache_key, error_metadata)
        return False
    
