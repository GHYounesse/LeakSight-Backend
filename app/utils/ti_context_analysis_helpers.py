

from app.crud.enrichment.context_analysis_service import ContextAnalysisService
# Dependency to get context analysis service
async def get_context_service():
    return ContextAnalysisService()
