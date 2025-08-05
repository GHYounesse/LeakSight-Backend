from fastapi import FastAPI, HTTPException, BackgroundTasks,APIRouter,Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.crud.enrichment_crud import EnrichmentCRUD
from app.crud.enrichment.context_analysis_service import ContextAnalysisService
from app.utils.ti_context_analysis_helpers import get_context_service
from app.api.auth import get_current_active_user
from app.models.auth import UserInDB


# Pydantic models
class IOCAnalysisRequest(BaseModel):
    ioc: str = Field(..., description="Indicator of Compromise to analyze")
    ioc_type: str = Field(..., description="Type of IOC (ip, domain, hash, url, etc.)")
    sources: Optional[List[str]] = Field(default=None, description="Specific sources to use")
    priority: Optional[str] = Field(default="normal", description="Analysis priority")

class BulkAnalysisRequest(BaseModel):
    iocs: List[Dict[str, str]] = Field(..., description="List of IOCs with their types")
    sources: Optional[List[str]] = Field(default=None, description="Specific sources to use")
    priority: Optional[str] = Field(default="normal", description="Analysis priority")

class ReAnalysisRequest(BaseModel):
    ioc: str = Field(..., description="IOC to re-analyze")
    force_refresh: Optional[bool] = Field(default=False, description="Force refresh from all sources")
    sources: Optional[List[str]] = Field(default=None, description="Specific sources to re-analyze")

class AnalysisResponse(BaseModel):
    job_id: str
    status: str
    message: str
    estimated_completion: Optional[datetime] = None

class StatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    total_iocs: int
    completed_iocs: int
    results: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

# Helper functions


enrichment_router = APIRouter(prefix="/api/v1/enrichment", tags=["THREAT INTELLIGENCE ENRICHMENT"])

# Endpoints
@enrichment_router.post("/analyze", response_model=AnalysisResponse)
async def analyze_ioc(request: IOCAnalysisRequest, background_tasks: BackgroundTasks,service: ContextAnalysisService = Depends(get_context_service),current_user: UserInDB = Depends(get_current_active_user)):
    """Analyze single IOC with all sources"""
    try:
        enrichment_crud=EnrichmentCRUD() 
        ioc_data = {
            "ioc": request.ioc,
            "ioc_type": request.ioc_type
        }
        
        job_id = await enrichment_crud.create_analysis_job(ioc_data, "single")
        
        # Start background analysis
        background_tasks.add_task(enrichment_crud.perform_analysis, job_id, ioc_data, "single",service)
        
        return AnalysisResponse(
            job_id=job_id,
            status="accepted",
            message="Analysis job started",
            estimated_completion=datetime.utcnow()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start analysis: {str(e)}")

@enrichment_router.post("/bulk-analyze", response_model=AnalysisResponse)
async def bulk_analyze_iocs(request: BulkAnalysisRequest, background_tasks: BackgroundTasks,service: ContextAnalysisService = Depends(get_context_service),current_user: UserInDB = Depends(get_current_active_user)):
    """Bulk analysis of multiple IOCs"""
    try:
        enrichment_crud=EnrichmentCRUD() 
        if not request.iocs:
            raise HTTPException(status_code=400, detail="No IOCs provided for analysis")
        
        ioc_data = {
            "iocs": request.iocs,
            "sources": request.sources,
            "priority": request.priority
        }
        
        job_id = await enrichment_crud.create_analysis_job(ioc_data, "bulk")
        
        # Start background analysis
        background_tasks.add_task(enrichment_crud.perform_analysis, job_id, ioc_data, "bulk",service)
        
        return AnalysisResponse(
            job_id=job_id,
            status="accepted",
            message=f"Bulk analysis job started for {len(request.iocs)} IOCs",
            estimated_completion=datetime.utcnow()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start bulk analysis: {str(e)}")

@enrichment_router.get("/status/{job_id}", response_model=StatusResponse)
async def get_analysis_status(job_id: str,current_user: UserInDB = Depends(get_current_active_user)):
    """Check analysis status"""
    try:
        enrichment_crud=EnrichmentCRUD()   # Replace with your actual import
        
        job = await enrichment_crud.get_analysis_job(job_id)
        
        if not job:
            raise HTTPException(status_code=404, detail="Analysis job not found")
        
        return StatusResponse(
            job_id=job["job_id"],
            status=job["status"],
            progress=job["progress"],
            total_iocs=job["total_iocs"],
            completed_iocs=job["completed_iocs"],
            results=job.get("results"),
            error=job.get("error"),
            created_at=job["created_at"],
            updated_at=job["updated_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get job status: {str(e)}")

@enrichment_router.post("/re-analyze", response_model=AnalysisResponse)
async def re_analyze_ioc(request: ReAnalysisRequest, background_tasks: BackgroundTasks,service: ContextAnalysisService = Depends(get_context_service),current_user: UserInDB = Depends(get_current_active_user)):
    """Re-analyze existing IOC"""
    try:
        enrichment_crud=EnrichmentCRUD()  # Replace with your actual import
        
        # Check if IOC exists in previous analyses (optional)
        if not request.force_refresh:
            # You might want to check if the IOC was recently analyzed
            # and return cached results if still valid
            pass
        
        ioc_data = {
            "ioc": request.ioc,
            "ioc_type": "unknown",  # You might want to detect this or require it
            "sources": request.sources,
            "force_refresh": request.force_refresh
        }
        
        job_id = await enrichment_crud.create_analysis_job(ioc_data, "re-analysis")
        
        # Start background analysis
        background_tasks.add_task(enrichment_crud.perform_analysis, job_id, ioc_data, "re-analysis",service)
        
        return AnalysisResponse(
            job_id=job_id,
            status="accepted",
            message="Re-analysis job started",
            estimated_completion=datetime.utcnow()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start re-analysis: {str(e)}")
