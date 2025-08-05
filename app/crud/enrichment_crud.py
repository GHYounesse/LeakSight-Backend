from typing import Optional, List
from datetime import datetime, timedelta
# from bson import ObjectId
# from pymongo import ReturnDocument
# from fastapi import HTTPException, status, Depends
# from app.models import UserCreate, UserInDB, UserUpdate, UserResponse
from app.services import auth_service
# from app.models.enums import UserStatus
from app.config import settings
from app.models.enrichment.models import IOCRequest

  # Assuming users is the collection for user data
from app.database import db
import uuid
# from app.dependencies import get_current_user
# from app.api.ioc import IOCCreate,IOCResponse
# from app.api.ioc import IOCBulkCreate,FailedIOC
from pymongo import DESCENDING
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import asyncio
from app.crud.enrichment.context_analysis_service import ContextAnalysisService
def generate_ioc_id() -> str:
        """Generate unique IOC ID"""
        return str(uuid.uuid4())
class EnrichmentCRUD:
    def __init__(self):
        
        
        if db.enrichment is None:
            raise RuntimeError("Enrichment collection not initialized")
        self.collection = db.enrichment
        if db.analysis_jobs is None:
            raise RuntimeError("analysis_jobs collection not initialized")
        self.analysis_jobs = db.analysis_jobs
        
    async def create_analysis_job(self, ioc_data: Dict[str, Any], job_type: str) -> str:
        """Create a new analysis job in the database"""
        job_id = str(uuid.uuid4())
        job_doc = {
            "job_id": job_id,
            "job_type": job_type,
            "status": "pending",
            "progress": 0,
            "total_iocs": len(ioc_data.get("iocs", [ioc_data.get("ioc")])),
            "completed_iocs": 0,
            "ioc_data": ioc_data,
            "results": [],
            "error": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        await self.analysis_jobs.insert_one(job_doc)
        return job_id

    async def get_analysis_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve analysis job by ID"""
        return await db.analysis_jobs.find_one({"job_id": job_id})

    async def update_job_status(self, job_id: str, status: str, progress: int = None, 
                            completed_iocs: int = None, error: str = None):
        """Update job status in database"""
        update_data = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if progress is not None:
            update_data["progress"] = progress
        if completed_iocs is not None:
            update_data["completed_iocs"] = completed_iocs
        if error is not None:
            update_data["error"] = error
        
        await db.analysis_jobs.update_one(
            {"job_id": job_id},
            {"$set": update_data}
        )

    async def analyze_ioc_with_sources(self,ioc: str, ioc_type: str,service: ContextAnalysisService) -> Dict[str, Any]:
        """Analyze IOC with all configured sources"""
        # This is where you'd implement your actual enrichment logic
        ioc_request = IOCRequest(ioc=ioc, ioc_type=ioc_type)
        result =await service.analyze_ioc(ioc_request)
        
        return result

    async def perform_analysis(self, job_id: str, ioc_data: Dict[str, Any], job_type: str,service):
        """Background task to perform actual analysis"""
        try:
            await self.update_job_status(job_id, "running", 0, 0)
            
            if job_type == "bulk":
                iocs = ioc_data["iocs"]
                total = len(iocs)
                results = []
                
                for i, ioc_info in enumerate(iocs):
                    result = await self.analyze_ioc_with_sources(
                        ioc_info["ioc"], 
                        ioc_info["ioc_type"], 
                        service
                    )
                    results.append(result)
                    
                    # Update progress
                    progress = int((i + 1) / total * 100)
                    await self.update_job_status( job_id, "running", progress, i + 1)
                    
                    # Store intermediate results
                    await db.analysis_jobs.update_one(
                        {"job_id": job_id},
                        {"$set": {"results": results}}
                    )
            
            else:  # single analysis or re-analysis
                result = await self.analyze_ioc_with_sources(
                    ioc_data["ioc"], 
                    ioc_data["ioc_type"], 
                    service
                )
                results = [result]
                await self.update_job_status( job_id, "running", 100, 1)
                
                # Store results
                await db.analysis_jobs.update_one(
                    {"job_id": job_id},
                    {"$set": {"results": results}}
                )
            
            await self.update_job_status(job_id, "completed", 100, len(results))
            
        except Exception as e:
            await self.update_job_status(job_id, "failed", error=str(e))
    
    