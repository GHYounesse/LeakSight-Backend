
from app.models.enrichment.models import ThreatContext, IOCRequest, AnalysisResult
from app.crud.enrichment.context_analysis_service import ContextAnalysisService
from app.dependencies import  logger
# Dependency to get context analysis service
async def get_context_service():
    return ContextAnalysisService()

# Background task for async analysis
async def analyze_ioc_background(job_id: str, ioc_request: IOCRequest):
    """Background task for IOC analysis"""
    try:
        service = ContextAnalysisService()
        result = await service.analyze_ioc(ioc_request)
        
        # Store result in Redis with job_id
        analysis_result = AnalysisResult(
            job_id=job_id,
            status="completed",
            threat_context=result
        )
        
        #redis_client.setex(f"analysis_job:{job_id}", 3600, analysis_result.json())
        logger.info(f"Background analysis completed for job {job_id}")
        
    except Exception as e:
        logger.error(f"Background analysis failed for job {job_id}: {str(e)}")
        
        error_result = AnalysisResult(
            job_id=job_id,
            status="failed",
            error_message=str(e)
        )
        
        #redis_client.setex(f"analysis_job:{job_id}", 3600, error_result.json())
