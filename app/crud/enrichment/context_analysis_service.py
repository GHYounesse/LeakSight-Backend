
from typing import Dict, Any
from app.models.enrichment.models import ThreatContext, IOCType, IOCRequest
from datetime import datetime
import json
from .threat_intelligence_engine import ThreatIntelligenceEngine
from fastapi import  HTTPException
from app.dependencies import  logger

class ContextAnalysisService:
    def __init__(self):
        self.engine = None
        
    async def analyze_ioc(self, ioc_request: IOCRequest) -> ThreatContext:
        """Analyze IOC and build threat context"""
        start_time = datetime.utcnow()
        
        # Perform analysis
        async with ThreatIntelligenceEngine() as engine:
            if ioc_request.ioc_type == IOCType.HASH:
                analysis_result = await engine.analyze_hash(ioc_request.ioc)
            elif ioc_request.ioc_type == IOCType.DOMAIN:
                analysis_result = await engine.analyze_domain(ioc_request.ioc)
            elif ioc_request.ioc_type == IOCType.IP:
                analysis_result = await engine.analyze_ip(ioc_request.ioc)
            elif ioc_request.ioc_type == IOCType.URL:
                analysis_result = await engine.analyze_url(ioc_request.ioc)
            else:
                raise HTTPException(status_code=400, detail=f"Unsupported IOC type: {ioc_request.ioc_type}")
        
        # Build threat context
        threat_context = self._build_threat_context(ioc_request, analysis_result)
        threat_context =json.loads(threat_context)
        
        processing_time = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"Analysis completed for {ioc_request.ioc} in {processing_time:.2f}s")
        
        return threat_context
    
    
    def _build_threat_context(self, ioc_request: IOCRequest, analysis_result: Dict[str, Any]):
        """Build ThreatContext from analysis results"""
        

        def flatten_list(data):
            """Helper to flatten one level of nested lists."""
            if not isinstance(data, list):
                return [data]
            flattened = []
            for item in data:
                if isinstance(item, list):
                    flattened.extend(item)
                else:
                    flattened.append(item)
            return flattened

        sources = analysis_result.get("sources", [])
        references_raw = analysis_result.get("references", [])
        references_list = flatten_list(references_raw)
        references_str = ", ".join(str(ref) for ref in references_list)

        targeted_countries_raw = analysis_result.get("targeted_countries", [])
        flat_countries = flatten_list(targeted_countries_raw)

        tags_raw = analysis_result.get("tags", [])
        flattened_tags = flatten_list(tags_raw)

        techniques_raw = analysis_result.get("attack_techniques", [])
        formatted_techniques = []

        for entry in flatten_list(techniques_raw):
            if isinstance(entry, dict):
                display = entry.get("display_name") or f"{entry.get('id', '')} - {entry.get('name', '')}"
                formatted_techniques.append(display)
            else:
                formatted_techniques.append(str(entry))

        
        result=json.dumps(analysis_result, indent=4)
        return result
