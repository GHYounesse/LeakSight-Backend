from fastapi import HTTPException,APIRouter,Depends
from datetime import datetime
from app.crud.enrichment.context_analysis_service import ContextAnalysisService
from app.utils.ti_context_analysis_helpers import get_context_service
from app.api.auth import get_current_active_user
from app.models.auth import UserInDB
from app.models.enrichment.models import IOCAnalysisRequest,IOCRequest

enrichment_router = APIRouter(prefix="/api/v1/enrichment", tags=["Threat Intelligence Enrichment"])

# Endpoints
@enrichment_router.post("/analyze")
async def analyze_ioc(request: IOCAnalysisRequest,service: ContextAnalysisService = Depends(get_context_service),current_user: UserInDB = Depends(get_current_active_user)):
    """Analyze single IOC with all sources"""
    try:
        
        ioc_request = IOCRequest(ioc=request.ioc, ioc_type=request.ioc_type)
        
        result =await service.analyze_ioc(ioc_request)
        
        
        return {
            "ioc": ioc_request.ioc,
            "ioc_type": ioc_request.ioc_type,
            "result": result,
            "created_at": datetime.utcnow()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to  analyse: {str(e)}")

# @enrichment_router.post("/bulk-analyze", response_model=AnalysisResponse)
# async def bulk_analyze_iocs(request: BulkAnalysisRequest, background_tasks: BackgroundTasks,service: ContextAnalysisService = Depends(get_context_service),current_user: UserInDB = Depends(get_current_active_user)):
#     """Bulk analysis of multiple IOCs"""
#     try:
#         enrichment_crud=EnrichmentCRUD() 
#         if not request.iocs:
#             raise HTTPException(status_code=400, detail="No IOCs provided for analysis")
        
#         ioc_data = {
#             "iocs": request.iocs,
#             "sources": request.sources,
#             "priority": request.priority
#         }
        
#         job_id = await enrichment_crud.create_analysis_job(ioc_data, "bulk")
        
#         # Start background analysis
#         background_tasks.add_task(enrichment_crud.perform_analysis, job_id, ioc_data, "bulk",service)
        
#         return AnalysisResponse(
#             job_id=job_id,
#             status="accepted",
#             message=f"Bulk analysis job started for {len(request.iocs)} IOCs",
#             estimated_completion=datetime.utcnow()
#         )
        
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to start bulk analysis: {str(e)}")

