import asyncio
import json
import aiohttp
import feedparser
from app.crud.feed_sources import feeds
from typing import Dict, List, Any
from datetime import datetime
import re
from app.database import db
from app.dependencies import logger
from pymongo import UpdateOne

class FeedModel:
    """Data model for normalized feed items"""
    
    def __init__(self, data: Dict[str, Any]):
        self.title = data.get('title', '')
        self.link = data.get('link', '')
        self.published_date = data.get('publishedDate', '')
        self.summary = data.get('summary', '')
        self.content = data.get('content', '')
        self.source = data.get('source', '')
        self.categories = data.get('categories', [])
        self.priority = data.get('priority', 'Information')
        
        # Additional metadata
        self.processed_at = datetime.utcnow().isoformat()
        self.model_used = "llama3.2:3b"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'title': self.title,
            'link': self.link,
            'publishedDate': self.published_date,
            'summary': self.summary,
            'content': self.content,
            'source': self.source,
            'categories': self.categories,
            'priority': self.priority,
            'processed_at': self.processed_at,
            'model_used': self.model_used
        }
    def __getitem__(self, key):
        return self.to_dict()[key]

class LlamaRSSNormalizer:
    """RSS Feed normalizer using local Llama 3.2:3b model"""
    
    def __init__(self, model_name: str = "llama3.2:3b"):
        self.model_name = model_name
        self.base_url = "http://localhost:11434"
        self.session = None
        if db.feeds is None:
            raise RuntimeError("Feeds collection not initialized")
        self.collection = db.feeds
        
    async def __aenter__(self):
        """Async context manager entry"""
        # Check if Ollama is running
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=300)
            )
            
            async with self.session.get(f"{self.base_url}/api/tags") as response:
                if response.status != 200:
                    raise Exception("Ollama service not running")
                    
            logger.info(f"✅ Connected to Ollama with model {self.model_name}")
            return self
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to Ollama: {e}")
            logger.error("Make sure Ollama is running: 'ollama serve'")
            raise
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def clean_html(self, text: str) -> str:
        """Remove HTML tags and clean text"""
        if not text:
            return ""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        # Clean up whitespace
        text = ' '.join(text.split())
        return text
    
    
    def prepare_rss_item_json(self, item: Dict) -> Dict[str, Any]:
        """Prepare minimal RSS item for LLM"""
        summary = self.clean_html(item.get('summary', ''))
        description = self.clean_html(item.get('description', ''))

        # Use summary if available; fall back to description
        short_content = summary if summary else description

        return {
            'title': item.get('title', '')[:200],
            'link': item.get('link', ''),
            'published': item.get('published', ''),
            'content': short_content[:300],  # trim for LLM
            'tags': [tag.get('term', str(tag)) if isinstance(tag, dict) else str(tag)
                    for tag in item.get('tags', [])]
        }

    async def call_llama(self, prompt: str) -> str:
        """Optimized Llama call with better parameters"""
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,  # Increased for faster generation
                "num_predict": 150,  # Reduced token limit
                "top_p": 0.8,        # Slightly more focused
                "top_k": 20,         # Add top_k for faster sampling
                "repeat_penalty": 1.1,
                "num_thread": 4,     # Use all logical cores
                "num_ctx": 1024,     # Smaller context window
                "stop": ["}"]        # Stop after JSON closes
            }
        }

        url = f"{self.base_url}/api/generate"
        
        # Reduced timeout since we expect faster responses
        timeout = aiohttp.ClientTimeout(total=300)  # 2 minutes max

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        response_text = result.get("response", "")
                        if response_text:
                            logger.debug(f"🧠 Llama response: {response_text[:100]}...")
                            return response_text
                        else:
                            logger.warning("⚠️ Llama returned empty response")
                            return ""
                    else:
                        error_text = await response.text()
                        logger.error(f"❌ Llama API error {response.status}: {error_text}")
                        return ""

        except asyncio.TimeoutError:
            logger.error("⏳ Timeout - response took >120s")
            return ""
        except Exception as e:
            logger.error(f"🔥 Error during Llama call: {e}")
            return ""

    def build_normalization_prompt(self, rss_item_json: Dict, source_name: str) -> str:
        """Shorter, more direct prompt for faster processing"""
        return f"""Convert RSS item to JSON format:

            {{"title":"","link":"","publishedDate":"","summary":"","content":"","source":"{source_name}","categories":[],"priority":""}}

            Priority rules:
            High: vulnerability, zero-day, exploit, ransomware, RCE, SQLi, XSS, breach
            Medium: patch, intel, cloud, DoS  
            Low: practices, IoT, updates
            Information: events, news

            Input: {json.dumps(rss_item_json, separators=(',', ':'))}

            JSON only:"""
    def parse_llama_response(self, response: str) -> Dict[str, Any]:
        """Parse and validate Llama response"""
        try:
            # Clean response
            response = response.strip()
            
            # Remove markdown code blocks if present
            if response.startswith("```json"):
                response = response[7:]
            elif response.startswith("```"):
                response = response[3:]
            
            if response.endswith("```"):
                response = response[:-3]
            
            # Find JSON object boundaries
            start_idx = response.find('{')
            end_idx = response.rfind('}')
            
            if start_idx != -1 and end_idx != -1:
                json_str = response[start_idx:end_idx+1]
                parsed = json.loads(json_str)
                
                # Validate required fields
                required_fields = ['title', 'link', 'publishedDate', 'summary', 'content', 'source', 'categories', 'priority']
                for field in required_fields:
                    if field not in parsed:
                        parsed[field] = ""
                
                # Ensure categories is a list
                if not isinstance(parsed.get('categories'), list):
                    parsed['categories'] = []
                
                # Validate priority
                valid_priorities = ['High', 'Medium', 'Low', 'Information']
                if parsed.get('priority') not in valid_priorities:
                    parsed['priority'] = 'Information'
                
                return parsed
                
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error: {e}")
        except Exception as e:
            logger.error(f"Response parsing error: {e}")
        
        # Return fallback structure
        return {
            "title": "Parse Error",
            "link": "",
            "publishedDate": datetime.utcnow().isoformat(),
            "summary": "Failed to parse AI response",
            "content": "AI response parsing failed",
            "source": "Unknown",
            "categories": ["error"],
            "priority": "Information"
        }
    
    async def normalize_item(self, item: Dict, source_name: str) -> FeedModel:
        """Normalize a single RSS item using Llama"""
        try:
            # Prepare item for processing
            rss_item_json = self.prepare_rss_item_json(item)
            
            # Build prompt
            prompt = self.build_normalization_prompt(rss_item_json, source_name)
            
            # Call Llama
            logger.info(f"🤖 Processing: {item.get('title', 'Untitled')[:60]}...")
            response = await self.call_llama(prompt)
            
            # Parse response
            normalized_data = self.parse_llama_response(response)
            normalized_data['source'] = source_name  # Ensure source is set
            
            return FeedModel(normalized_data)
            
        except Exception as e:
            logger.error(f"Item normalization failed: {e}")
            # Return fallback model
            fallback_data = {
                "title": item.get('title', 'Error'),
                "link": item.get('link', ''),
                "publishedDate": item.get('published', datetime.utcnow().isoformat()),
                "summary": self.clean_html(item.get('summary', '')[:200]),
                "content": self.clean_html(item.get('description', '')[:200]),
                "source": source_name,
                "categories": [tag.get('term', str(tag)) if isinstance(tag, dict) else str(tag) 
                              for tag in item.get('tags', [])],
                "priority": "Information"
            }
            return FeedModel(fallback_data)
        

    
    async def bulk_upsert(self, documents: List[Dict[str, Any]]) -> Dict[str, int]:
        if not documents:
            return {"inserted": 0, "modified": 0}

        operations = []

        for doc in documents:
            doc_dict = doc.to_dict() if hasattr(doc, "to_dict") else doc
            link = doc_dict.get("link", "").strip()
            if not link:
                continue
            cleaned_doc = {k: v for k, v in doc_dict.items() if v not in [None, ""]}

            operations.append(
                UpdateOne(
                    {"link": link},
                    {"$set": cleaned_doc},
                    upsert=True
                )
            )

        if not operations:
            return {"inserted": 0, "modified": 0}

        try:
            result = await self.collection.bulk_write(operations, ordered=False)
            return {
                "inserted": result.upserted_count or 0,
                "modified": result.modified_count or 0
            }
        except Exception as e:
            logger.error(f"Bulk upsert error: {e}")
            return {"inserted": 0, "modified": 0}

    async def bulk_upsert_test(self) -> Dict[str, int]:
        try:
            operations = [{
                    "updateOne": {
                        "filter": {"link": "https://example.com"},
                        "update": {"$set": {"title": "test", "link": "https://example.com"}},
                        "upsert": True
                    }
                }]

            result = await self.collection.bulk_write(operations, ordered=False)
            
            return {"inserted": 99, "modified": 99}
        except Exception as e:
            logger.error(f"Bulk upsert error: {e}")
            return {"inserted": 0, "modified": 0}



 
async def process_feeds_with_llama(feeds: List[Dict[str, str]]) -> List[FeedModel]:
    """Process RSS feeds using local Llama model"""
    
    MAX_ITEMS_PER_FEED = 3  # Limit items per feed
    MAX_CONCURRENT_ITEMS = 3  # Process 2 items at once
    
    logger.info("🚀 Starting RSS Feed Normalization with Llama 3.2:3b")
    logger.info("=" * 60)
    
    all_normalized_items = []
    
    async with LlamaRSSNormalizer() as normalizer:
        for feed_info in feeds:
            feed_url = feed_info["feed_url"]
            source_name = feed_info["feed_source"]
            
            try:
                logger.info(f"📡 Fetching feed from {source_name}...")
                
                # Parse RSS feed
                feed = feedparser.parse(feed_url)
                logger.info(f"Found {len(feed.entries)} entries in {source_name}")
                
                # Limit items for processing
                items_to_process = feed.entries[:MAX_ITEMS_PER_FEED]
                
                # Process items in small batches
                semaphore = asyncio.Semaphore(MAX_CONCURRENT_ITEMS)
                
                async def process_single_item(item):
                    async with semaphore:
                        return await normalizer.normalize_item(item, source_name)
                
                # Process all items for this feed
                tasks = [process_single_item(item) for item in items_to_process]
                feed_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Collect successful results
                for result in feed_results:
                    
                    if isinstance(result, FeedModel):
                        all_normalized_items.append(result)
                        logger.info(f"✅ Normalized: {result.title[:60]}... [Priority: {result.priority}]")
                    else:
                        logger.error(f"Failed to process item: {result}")
                

                if all_normalized_items:
                    logger.info(f"💾 Saving {len(all_normalized_items)} total entries to MongoDB...")
                    result = await normalizer.bulk_upsert(all_normalized_items)
                    #result=await normalizer.bulk_upsert_test()
                    logger.info(f"✅ Inserted: {result['inserted']}, Modified: {result['modified']}")
                else:
                    logger.warning("⚠️ No data to save")

                
                logger.info(f"📄 Completed {source_name}: {len([r for r in feed_results if isinstance(r, FeedModel)])} items processed")
                
                # Small delay between feeds
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"❌ Failed to process feed {source_name}: {e}")
    
    logger.info("📊 Processing Summary:")
    logger.info(f"   Total items normalized: {len(all_normalized_items)}")
    
    # Priority breakdown
    priority_counts = {}
    for item in all_normalized_items:
        priority_counts[item.priority] = priority_counts.get(item.priority, 0) + 1
    
    logger.info(f"   Priority breakdown: {priority_counts}")
    logger.info("=" * 60)
    
    return all_normalized_items
 

async def periodic_process_feeds(interval_hours: int = 1):
    while True:
        try:
            await asyncio.wait_for(process_feeds_with_llama(feeds), timeout=interval_hours * 3600)
        except asyncio.TimeoutError:
            logger.error("Threat intel collection timed out")
        except Exception as e:
            logger.error(f"Periodic collection failed: {e}")
        await asyncio.sleep(interval_hours * 3600)


