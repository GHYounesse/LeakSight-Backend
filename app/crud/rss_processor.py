from app.database import db
import asyncio
import aiohttp
import json
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from bs4 import BeautifulSoup
import feedparser
from bson import ObjectId
from typing import List, Dict, Any
from app.config import settings
from pydantic import validator
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
    
    def clean_text(self, html: str) -> str:
        """Clean HTML content and extract text"""
        return BeautifulSoup(html or "", "html.parser").text.strip()
    
    def build_prompt(self, item: Dict[str, Any], source_name: str) -> str:
        """Build prompt for Groq API normalization"""
        title = item.get("title", "")
        link = item.get("link", "")
        pub_date = item.get("published_parsed")
        publishedDate = (
            datetime(*pub_date[:6]).isoformat() + "Z" if pub_date else None
        )
        
        summary = self.clean_text(item.get("summary", item.get("description", "")))[:800]
        content = item.get("content", [{"value": item.get("summary", "")}])[0].get("value", "")
        if len(content) > 800:
            content = content[:800] + "..."

        categories = [tag['term'] for tag in item.get("tags", [])] if "tags" in item else []

        # Special handling for MITRE feed items
        if source_name == "MITRE CVE":
            summary = f"CVE entry: {title}"
            content = f"Published: {publishedDate or 'Unknown'} - {summary}"

        rss_item_json = {
            "title": title,
            "link": link,
            "publishedDate": publishedDate,
            "summary": summary,
            "content": content,
            "source": source_name,
            "categories": categories
        }

        prompt = f"""
        You are a cybersecurity RSS feed normalizer and analyst.
        Given the following RSS feed item JSON and the source name "{source_name}", generate a clean, well-structured JSON object with the following fields:
        {{
        "title": "string",
        "link": "string (URL)",
        "publishedDate": "ISO 8601 UTC string (e.g., 2025-06-24T12:34:56Z)",
        "summary": "string (plaintext, max 2 concise lines or ~2 sentences)",
        "content": "string (HTML or plaintext, max 2 concise lines or ~2 sentences)",
        "source": "string",
        "categories": ["array of strings"],
        "priority": "string (one of: High, Medium, Low, Information)"
        }}
        **Rules**:
        1. Extract and clean each field based on the input JSON.
        2. The 'summary' and 'description' must be a short and clear 2-line summary (~2 sentences). Avoid long descriptions.
        3. Prioritize based on the content or title using these rules:
           - High: vulnerability, zero-day, exploit, ransomware, critical breach, Remote Code Execution, SQLi, XSS, Command Injection, Buffer Overflow
           - Medium: patch, threat intel, cloud security, incident response, DoS, Denial of Service, Information Disclosure
           - Low: best practices, IoT security, general updates, configuration guides
           - Information: announcements, events, non-critical news, informational
        4. Ensure the output is strictly a valid JSON object. Do not wrap in markdown (no ```), and do not include comments or explanations and make sure it ends with a closing brace and double quote.
        **Input RSS item JSON**:
        {json.dumps(rss_item_json, indent=2)}
        """
        return prompt
    
    async def call_groq(self, prompt: str) -> str:
        """Async call to Groq API"""
        data = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": "You are a strict JSON generator. Always return a single, clean JSON object. No markdown, no commentary."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0,
            "max_tokens": 512
        }
        
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                async with self.session.post(GROQ_API_URL, json=data, headers=headers) as response:
                    response.raise_for_status()
                    result = await response.json()
                    return result["choices"][0]["message"]["content"].strip()
            except Exception as e:
                logger.warning(f"Groq API attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise
    
    def try_safe_json_load(self, text: str) -> Dict[str, Any]:
        """Safely load JSON with error handling"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Attempting to fix malformed JSON...")
            fixed = text.strip()
            if not fixed.endswith("}"):
                fixed += '"}' if fixed.endswith('"') else '"}'
            try:
                return json.loads(fixed)
            except Exception as e:
                logger.error(f"JSON parsing failed: {e}")
                raise
    
    async def fetch_and_process_feed(self, feed_info: Dict[str, str]) -> List[Dict[str, Any]]:
        """Fetch and process RSS feed entries"""
        MAX_ITEMS = 2
        
        feed_url = feed_info["feed_url"]
        source_name = feed_info["feed_source"]
        
        try:
            # Parse RSS feed (feedparser is synchronous)
            feed = feedparser.parse(feed_url)
            # print("feed:", feed)
            logger.info(f"Fetched {len(feed.entries)} entries from {source_name}")
            
            normalized_entries = []
            
            for i, item in enumerate(feed.entries[:MAX_ITEMS]):
                try:
                    prompt = self.build_prompt(item, source_name)
                    logger.info(f"Processing: [{source_name}] {item.get('title', '')}")
                    
                    ai_response = await self.call_groq(prompt)
                    normalized = self.try_safe_json_load(ai_response)
                    normalized_entries.append(normalized)
                    
                    # Rate limiting
                    await asyncio.sleep(2.5)
                    
                except Exception as e:
                    logger.error(f"Failed to process item {i+1} from {source_name}: {e}")
            
            await asyncio.sleep(5)  # Delay between feeds
            return normalized_entries
            
        except Exception as e:
            logger.error(f"Failed to process feed {source_name}: {e}")
            return []
    async def ensure_indexes(self):
        """Create necessary indexes"""
        try:
            await self.collection.create_index("link", unique=True)
            logger.info("Indexes created successfully")
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")
    
    async def bulk_upsert(self, documents: List[Dict[str, Any]]) -> Dict[str, int]:
        """Bulk upsert documents"""
        if not documents:
            return {"inserted": 0, "modified": 0}
        
        operations = []
        for doc in documents:
            operations.append({
                "updateOne": {
                    "filter": {"link": doc["link"]},
                    "update": {"$set": doc},
                    "upsert": True
                }
            })
        
        try:
            result = await self.collection.bulk_write(operations, ordered=False)
            return {
                "inserted": result.upserted_count if result.upserted_count else 0,
                "modified": result.modified_count if result.modified_count else 0
            }
        except Exception as e:
            logger.error(f"Bulk upsert error: {e}")
            return {"inserted": 0, "modified": 0}
    
    async def get_feeds(self,limit,skip):
        
        
        # Get total count
        total_count = await self.collection.count_documents({})
        
        # Get feeds with pagination, sorted by publishedDate (newest first)
        cursor = self.collection.find({}).sort("publishedDate", -1).skip(skip).limit(limit)
        feeds_data = await cursor.to_list(length=limit)
        
        # Convert MongoDB documents to FeedItem models
        feeds = []
        for feed in feeds_data:
            feed["_id"] = str(feed["_id"])  # Convert ObjectId to string
            feeds.append(FeedItem(**feed))
            
        return feeds, total_count
    
    async def get_feeds_by_priority(self,priority,limit,skip):
        
        
        
        filter_query = {"priority": priority}
        
        # Get total count for this priority
        total_count = await self.collection.count_documents(filter_query)
        
        # Get feeds with pagination, sorted by publishedDate (newest first)
        cursor = self.collection.find(filter_query).sort("publishedDate", -1).skip(skip).limit(limit)
        feeds_data = await cursor.to_list(length=limit)
        
        # Convert MongoDB documents to FeedItem models
        feeds = []
        for feed in feeds_data:
            feed["_id"] = str(feed["_id"])  # Convert ObjectId to string
            feeds.append(FeedItem(**feed))
            
        return feeds, total_count

    async def get_feeds_by_source(self,source,limit,skip):
        
        
        
        filter_query = {"source": source}
        
        # Get total count for this source
        total_count = await self.collection.count_documents(filter_query)
        
        # Get feeds with pagination, sorted by publishedDate (newest first)
        cursor = self.collection.find(filter_query).sort("publishedDate", -1).skip(skip).limit(limit)
        feeds_data = await cursor.to_list(length=limit)
        
        # Convert MongoDB documents to FeedItem models
        feeds = []
        for feed in feeds_data:
            feed["_id"] = str(feed["_id"])  # Convert ObjectId to string
            feeds.append(FeedItem(**feed))
            
        return feeds, total_count

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
            print(f"Applied filters: {filters}")
            
            # Get total count with applied filters
            total_count = await self.collection.count_documents(filters)
            
            # Get filtered feeds with pagination
            cursor = self.collection.find(filters).sort("published_date", -1).skip(skip).limit(limit)
            feeds_data = await cursor.to_list(length=limit)
            
            feeds = []
            for feed in feeds_data:
                feed["_id"] = str(feed["_id"])  # Convert ObjectId to string
                feeds.append(FeedItem(**feed))
            return feeds, total_count
            
        except Exception as e:
            raise Exception(f"Error searching feeds: {str(e)}")
    
