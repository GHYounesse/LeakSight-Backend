# from typing import Optional, List
from datetime import datetime, timedelta
from bson import ObjectId
# from pymongo import ReturnDocument
from fastapi import HTTPException, status, Depends
# from app.models import UserCreate, UserInDB, UserUpdate, UserResponse
from app.services import auth_service
# from app.models.enums import UserStatus
from app.config import settings
  # Assuming users is the collection for user data
from app.database import db
import uuid
# from app.dependencies import get_current_user
from app.api.ioc import IOCCreate,IOCResponse
# from app.api.ioc import IOCBulkCreate,FailedIOC
from pymongo import DESCENDING
def generate_ioc_id() -> str:
        """Generate unique IOC ID"""
        return str(uuid.uuid4())
class IOCCRUD:
    def __init__(self):
        
        
        if db.iocs is None:
            raise RuntimeError("IoC collection not initialized")
        self.collection = db.iocs
        
       
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
        
        ioc_doc = {
            "id":ioc_id,
            "created_at":now,
            "updated_at":now,
            "created_by":current_user,
            "updated_by":current_user,
            "value": ioc.value,
            "type": ioc.type,
            "threat_level": ioc.threat_level,
            "status": ioc.status,
            "description": ioc.description,
            "source": ioc.source,
            "confidence": ioc.confidence,
            "tags": ioc.tags,
            "metadata": ioc.metadata,
            "expiration_date": ioc.expiration_date

        }
        print(ioc_doc)
        
        # Create user document
        
        
        result = await self.collection.insert_one(ioc_doc)
        ioc_doc["id"] = str(result.inserted_id)
        
        return IOCResponse(**ioc_doc)
    
      
    # async def create_ioc_bulk(self, bulk_request,current_user: str ):
    #     """Create bulk of iocs """
        
    #     failed=[]
    #     created=[]
    #     # Check if ioc already exists
    #     iocs = bulk_request.get("iocs", [])
    #     for i, ioc in enumerate(iocs):
    #         try:
    #             print("ioc:", ioc)
    #             # Check if IOC already exists
    #             existing_ioc = await self.collection.find_one({
    #                 "$or": [
    #                     {"value": ioc.value},
    #                     {"type": ioc.type}
    #                 ]
    #             })
                
    #             if existing_ioc:
    #                 failed.append({
    #                 "index": i,
    #                 "ioc": ioc,
    #                 "error":f"IOC with value '{ioc.value}' and type '{ioc.type}' already exists"
    #                 })
    #                 continue
                
    #             ioc_id = generate_ioc_id()
    #             now = datetime.utcnow()
                
    #             ioc_doc = {
    #                 "id":ioc_id,
    #                 "created_at":now,
    #                 "updated_at":now,
    #                 "created_by":current_user,
    #                 "updated_by":current_user,
    #                 "value": ioc.value,
    #                 "type": ioc.type,
    #                 "threat_level": ioc.threat_level,
    #                 "status": ioc.status,
    #                 "description": ioc.description,
    #                 "source": ioc.source,
    #                 "confidence": ioc.confidence,
    #                 "tags": ioc.tags,
    #                 "metadata": ioc.metadata,
    #                 "expiration_date": ioc.expiration_date

    #             }
                
    #             # Create user document
                
                
    #             result = await self.collection.insert_one(ioc_doc)
    #             ioc_doc["id"] = str(result.inserted_id)
    #             created.append(ioc_doc)    
                
                
                
    #         except Exception as e:
    #             failed.append({
    #                 "index": i,
    #                 "ioc": ioc,
    #                 "error": str(e)
    #             })

    #     return created,failed
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
            print("Error fetching IOC by ID:", e)
        return None
    
    async def delete_ioc_by_id(self, ioc_id: str) :
        """Get user by ID"""
        try:
            await self.collection.delete_one({"id": ioc_id})
            return True
        except Exception:
            return False
            print("Error deleting IOC by ID:", e)
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
    
    