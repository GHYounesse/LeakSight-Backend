
from datetime import datetime
from bson import ObjectId
from fastapi import HTTPException, status
from app.database import db
import uuid
from app.models.enrichment.models import IOCType
from app.models.ioc import IOCCreate,IOCResponse,IOC_TYPE_MAP
from pymongo import DESCENDING
from app.dependencies import logger
from typing import Dict, Any,List


def generate_ioc_id() -> str:
        """Generate unique IOC ID"""
        return str(uuid.uuid4())
import re
from ipaddress import ip_address
from enum import Enum

class IOCType(str, Enum):
    HASH = "hash"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"

# Regex for simple domain and URL detection
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
URL_REGEX = re.compile(r"^(?:http|https)://[^\s/$.?#].[^\s]*$")

# Regex for common hash lengths
HASH_REGEXES = [
    re.compile(r"^[a-fA-F0-9]{32}$"),  # MD5
    re.compile(r"^[a-fA-F0-9]{40}$"),  # SHA1
    re.compile(r"^[a-fA-F0-9]{64}$"),  # SHA256
]

def detect_ioc_type(value: str) -> IOCType:
    value = value.strip()
    
    # 1. Check IP
    try:
        ip_address(value)
        return IOCType.IP
    except ValueError:
        pass

    # 2. Check URL
    if URL_REGEX.match(value):
        return IOCType.URL

    # 3. Check domain
    if DOMAIN_REGEX.match(value):
        return IOCType.DOMAIN

    # 4. Check hashes
    for regex in HASH_REGEXES:
        if regex.match(value):
            return IOCType.HASH

    # 5. Default fallback
    return IOCType.HASH

class IOCCRUD:
    def __init__(self):
                
        if db.iocs is None:
            raise RuntimeError("IoC collection not initialized")
        self.collection = db.iocs
        if db.pulses is None:
            raise RuntimeError("Pulse collection not initialized")
        self.pulses_collection = db.pulses

    async def create_ioc(self, ioc:IOCCreate,current_user: str):
        """Create a new user"""
        # Check if ioc already exists
        
        existing_ioc = await self.collection.find_one({
            "$and": [
                {"value": ioc.value},
                {"type": ioc.type}
            ]
        })
        
        if existing_ioc:
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="IOC already exists"
            )
        
        ioc_id = generate_ioc_id()
        now = datetime.utcnow()
        
        raw_type = getattr(ioc, "type", "")

        normalized_type = IOC_TYPE_MAP.get(raw_type, "file_hash")  # fallback if unknown

        ioc_doc = {
            "id": ioc_id,
            "created_at": now,
            "updated_at": now,
            "created_by": current_user,
            "updated_by": current_user,
            "value": getattr(ioc, "value", ""),
            "type": normalized_type,   # ✅ normalized
            "threat_level": getattr(ioc, "threat_level", "unknown"),
            "status": getattr(ioc, "status", "inactive"),
            "description": getattr(ioc, "description", ""),
            "source": getattr(ioc, "source", ""),
            "confidence": getattr(ioc, "confidence", 0),
            "tags": getattr(ioc, "tags", []),
            "metadata": getattr(ioc, "metadata", {}),
            "expiration_date": getattr(ioc, "expiration_date", None)
        }

        
        
        # Create user document
        
        
        result = await self.collection.insert_one(ioc_doc)
        ioc_doc["id"] = str(result.inserted_id)
        
        return IOCResponse(**ioc_doc)

    # async def create_ioc_auto(self, ioc:IOCCreate,pulse_id: str,current_user: str):
    #     """Create a new user"""
    #     # Check if ioc already exists
        
    #     existing_ioc = await self.collection.find_one({
    #         "$and": [
    #             {"value": ioc.value},
    #             {"type": ioc.type},
    #             {"pulse_id":pulse_id}
    #         ]
    #     })
        
    #     if existing_ioc:
            
    #         return None
        
    #     ioc_id = generate_ioc_id()
    #     now = datetime.utcnow()
        
        
    #     raw_type = getattr(ioc, "type", "")

    #     normalized_type = IOC_TYPE_MAP.get(raw_type, "file_hash")  # fallback if unknown

    #     ioc_doc = {
    #         "id": ioc_id,
    #         "pulse_id": pulse_id,
    #         "created_at": now,
    #         "updated_at": now,
    #         "created_by": current_user,
    #         "updated_by": current_user,
    #         "value": getattr(ioc, "value", ""),
    #         "type": normalized_type,   # ✅ normalized
    #         "threat_level": getattr(ioc, "threat_level", "unknown"),
    #         "status": getattr(ioc, "status", "inactive"),
    #         "description": getattr(ioc, "description", ""),
    #         "source": getattr(ioc, "source", ""),
    #         "confidence": getattr(ioc, "confidence", 0),
    #         "tags": getattr(ioc, "tags", []),
    #         "metadata": getattr(ioc, "metadata", {}),
    #         "expiration_date": getattr(ioc, "expiration_date", None)
    #     }

        
        
    #     # Create user document
        
        
    #     result = await self.collection.insert_one(ioc_doc)
    #     ioc_doc["id"] = str(result.inserted_id)
        
    #     return IOCResponse(**ioc_doc)

    # async def save_pulse(self, pulse: Dict[str, Any]) -> str:
    #     """
    #     Save filtered OTX pulse to MongoDB
    #     """
    #     existing_pulse = await self.pulses_collection.find_one({
    #         "$and": [
    #             {"pulse_id":pulse.get("id")}
    #         ]
    #     })
    #     if existing_pulse:
            
    #         return None
    #     pulse_doc = {
    #         "pulse_id": pulse.get("id"),
    #         "name": pulse.get("name"),
    #         "description": pulse.get("description"),
    #         "created": pulse.get("created"),
    #         "modified": pulse.get("modified"),
    #         "tlp": pulse.get("TLP"),
    #         "tags": pulse.get("tags", []),
    #         "references": pulse.get("references", []),
    #         "indicator_count": pulse.get("indicator_count"),
    #         "indicator_type_counts": pulse.get("indicator_type_counts", {}),
    #         "author": pulse.get("author", {}).get("username"),
    #         "public": bool(pulse.get("public", 0)),
    #     }

    #     result = await self.pulses_collection.insert_one(pulse_doc)
    #     return str(result.inserted_id)
    
    async def create_iocs_batch(self, iocs: List[IOCCreate], pulse_id: str, current_user: str) -> List[Dict[str, Any]]:
        """
        Create multiple IOCs in a batch operation for better performance.
        
        Returns:
            List of results with status for each IOC
        """
        results = []
        
        # Prepare all documents
        docs_to_insert = []
        for ioc in iocs:
            # Check for duplicates first
            ioc_type_value = getattr(ioc, "type", None)

            # 1. Check map first
            ioc_type = IOC_TYPE_MAP.get(ioc_type_value)

            # 2. If not in map, detect automatically
            if ioc_type is None:
                ioc_type = detect_ioc_type(getattr(ioc, "value", ""))
                
            existing_ioc = await self.collection.find_one({
                "value": ioc.value,
                "type": ioc_type,
                "pulse_id": pulse_id
            })
            
            if existing_ioc:
                results.append({"status": "exists", "ioc": ioc.value})
                continue
            
            ioc_id = generate_ioc_id()
            now = datetime.utcnow()
            
            ioc_doc = {
                "id": ioc_id,
                "pulse_id": pulse_id,
                "created_at": now,
                "updated_at": now,
                "created_by": current_user,
                "updated_by": current_user,
                "value": getattr(ioc, "value", ""),
                "type": ioc_type,
                "threat_level": getattr(ioc, "threat_level", "unknown"),
                "status": getattr(ioc, "status", "inactive"),
                "description": getattr(ioc, "description", ""),
                "source": getattr(ioc, "source", ""),
                "confidence": getattr(ioc, "confidence", 0),
                "tags": getattr(ioc, "tags", []),
                "metadata": getattr(ioc, "metadata", {}),
                "expiration_date": getattr(ioc, "expiration_date", None)
            }
            docs_to_insert.append(ioc_doc)
        
        # Batch insert
        if docs_to_insert:
            try:
                insert_result = await self.collection.insert_many(docs_to_insert, ordered=False)
                for doc in docs_to_insert:
                    results.append({"status": "created", "ioc": doc["value"]})
            except Exception as e:
                logger.error(f"Batch insert failed: {str(e)}")
                # Fall back to individual inserts
                for doc in docs_to_insert:
                    try:
                        await self.collection.insert_one(doc)
                        results.append({"status": "created", "ioc": doc["value"]})
                    except Exception:
                        results.append({"status": "error", "ioc": doc["value"]})
        
        return results

    async def save_pulse(self, pulse: Dict[str, Any]) -> Dict[str, Any]:
        """
        Save filtered OTX pulse to MongoDB with improved status reporting.
        
        Returns:
            Dict with status and message/id
        """
        try:
            pulse_id = pulse.get("id")
            if not pulse_id:
                return {"status": "error", "message": "Pulse missing ID"}
            
            existing_pulse = await self.pulses_collection.find_one({
                "pulse_id": pulse_id
            })
            
            if existing_pulse:
                return {"status": "exists", "id": str(existing_pulse["_id"])}
            
            pulse_doc = {
                "pulse_id": pulse_id,
                "name": pulse.get("name", ""),
                "description": pulse.get("description", ""),
                "created": pulse.get("created"),
                "modified": pulse.get("modified"),
                "tlp": pulse.get("TLP"),
                "tags": pulse.get("tags", []),
                "references": pulse.get("references", []),
                "indicator_count": pulse.get("indicator_count", 0),
                "indicator_type_counts": pulse.get("indicator_type_counts", {}),
                "author": pulse.get("author", {}).get("username"),
                "public": bool(pulse.get("public", 0)),
                "saved_at": datetime.utcnow()
            }

            result = await self.pulses_collection.insert_one(pulse_doc)
            return {"status": "created", "id": str(result.inserted_id)}
            
        except Exception as e:
            logger.error(f"Error saving pulse {pulse.get('id', 'unknown')}: {str(e)}")
            return {"status": "error", "message": str(e)}

    async def create_ioc_bulk(self, bulk_request, current_user: str):
        """Create bulk of iocs"""
        failed = []
        created = []

        iocs = bulk_request.get("iocs", [])
        for i, ioc in enumerate(iocs):
            try:
                existing_ioc = await self.collection.find_one({
                    "$and": [
                        {"value": ioc["value"]},
                        {"type": ioc["type"]}
                    ]
                })

                if existing_ioc:
                    failed.append({
                        "index": i,
                        "ioc": ioc,
                        "error": f"IOC with value '{ioc['value']}' and type '{ioc['type']}' already exists"
                    })
                    continue

                ioc_id = generate_ioc_id()
                now = datetime.utcnow()

                ioc_doc = {
                    "id": ioc_id,
                    "created_at": now,
                    "updated_at": now,
                    "created_by": current_user.id,
                    "updated_by": current_user.id,
                    "value": ioc["value"],
                    "type": ioc["type"],
                    "threat_level": ioc["threat_level"],
                    "status": ioc["status"],
                    "description": ioc["description"],
                    "source": ioc["source"],
                    "confidence": ioc["confidence"],
                    "tags": ioc.get("tags", []),
                    "metadata": ioc.get("metadata", {}),
                    "expiration_date": ioc.get("expiration_date")
                }

                result = await self.collection.insert_one(ioc_doc)
                ioc_doc["id"] = str(result.inserted_id)
                if "_id" in ioc_doc:
                    del ioc_doc["_id"]
                created.append(ioc_doc)

            except Exception as e:
                failed.append({
                    "index": i,
                    "ioc": ioc,
                    "error": str(e)
                })

        return created, failed

    async def get_filtered_iocs(self,type: str = None,
    threat_level: str = None,
    status: str = None,
    source: str = None,
    tag: str = None,
    search: str = None
    ):
        filter_dict = {}

        if type:
            filter_dict["type"] = type

        if threat_level:
            filter_dict["threat_level"] = threat_level

        if status:
            filter_dict["status"] = status

        if source:
            filter_dict["source"] = source

        if tag:
            filter_dict["tags"] = tag  # Assumes `tags` is an array in MongoDB

        if search:
            filter_dict["$or"] = [
                {"value": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}}
            ]

        cursor = self.collection.find(filter_dict).sort("created_at", DESCENDING)
        results = await cursor.to_list(length=None)
        return results
    
    
    async def get_ioc_by_id(self, ioc_id: str) :
        """Get user by ID"""
        try:
            ioc_doc = await self.collection.find_one({"id": ioc_id})
            if ioc_doc:
                ioc_doc["id"] = str(ioc_doc["_id"])  # Convert ObjectId to str
                del ioc_doc["_id"]  # Optional: remove _id if you don't want to expose it
                return ioc_doc
        except Exception:
            return None
            logger.error("Error fetching IOC by ID:", e)
        return None
    
    async def delete_ioc_by_id(self, ioc_id: str) :
        """Get user by ID"""
        try:
            await self.collection.delete_one({"id": ioc_id})
            return True
        except Exception as e:
            logger.error("Error deleting IOC by ID:", e)
            return False
            
        return False
    
    async def check_duplicate_ioc(self, ioc_id: str, new_value: str, new_type: str):
        """Raise exception if another IOC with same value and type exists"""
        duplicate = await self.collection.find_one({
            "_id": {"$ne": ObjectId(ioc_id)},  # Not the current document
            "value": new_value,
            "type": new_type
        })

        if duplicate:
            raise HTTPException(
                status_code=409,
                detail=f"IOC with value '{new_value}' and type '{new_type}' already exists"
            )
    
    async def update_ioc(self, ioc_id: str, ioc_update: dict, current_user: str):
        """Update IOC in MongoDB"""
        try:
            # Only include fields that are actually being updated
            update_data = ioc_update.dict(exclude_unset=True)

            update_data["updated_at"] = datetime.utcnow()
            update_data["updated_by"] = current_user

            result = await self.collection.update_one(
                {"_id": ObjectId(ioc_id)},
                {"$set": update_data}
            )

            if result.modified_count == 0:
                raise HTTPException(status_code=404, detail="IOC not found or no changes made")

            # Optional: fetch and return the updated IOC
            updated_ioc = await self.collection.find_one({"_id": ObjectId(ioc_id)})
            if updated_ioc:
                updated_ioc["id"] = str(updated_ioc["_id"])  # Convert ObjectId to str
                del updated_ioc["_id"]  # Optional: remove _id if you don't want to expose it
                return updated_ioc
            return updated_ioc

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    