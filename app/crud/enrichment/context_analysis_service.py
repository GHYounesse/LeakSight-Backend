import aiohttp
from typing import List ,Dict, Any
import asyncio
from .threat_intels import THREAT_INTEL_SOURCES
from app.models.enrichment.models import ThreatSeverity, ThreatContext, IOCType, IOCRequest, ThreatSource
from datetime import datetime
import json
import hashlib
from .threat_intelligence_engine import ThreatIntelligenceEngine
from fastapi import  HTTPException
from app.dependencies import  logger
class ContextAnalysisService:
    def __init__(self):
        self.engine = None
        
    async def analyze_ioc(self, ioc_request: IOCRequest) -> ThreatContext:
        """Analyze IOC and build threat context"""
        start_time = datetime.utcnow()
        
        # Check cache first
        #cache_key = f"threat_context:{ioc_request.ioc_type}:{hashlib.md5(ioc_request.ioc.encode()).hexdigest()}"
        # cached_result = redis_client.get(cache_key)
        
        # if cached_result:
        #     logger.info(f"Cache hit for {ioc_request.ioc}")
        #     return ThreatContext.parse_raw(cached_result)
        
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
        # Cache the result (expire in 1 hour)
        #redis_client.setex(cache_key, 3600, threat_context.json())
        
        processing_time = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"Analysis completed for {ioc_request.ioc} in {processing_time:.2f}s")
        
        return threat_context
    
    # def _build_threat_context(self, ioc_request: IOCRequest, analysis_result: Dict[str, Any]) -> ThreatContext:
    #     """Build ThreatContext from analysis results"""
    #     print("Made to threat context")
    #     sources =analysis_result.get("sources", [])
        
    #     refs = analysis_result.get("references", [])
    #     if isinstance(refs, list):
    #         # Flatten and join all URLs
    #         flattened = [item for sublist in refs for item in (sublist if isinstance(sublist, list) else [sublist])]
    #         references_str = ", ".join(flattened)
    #     else:
    #         references_str = str(refs)
        
    #     targeted_countries = analysis_result.get("targeted_countries", [])
    #     flat_countries = [country for sublist in targeted_countries for country in (sublist if isinstance(sublist, list) else [sublist])]

    #     # If nested:
    #     tags = analysis_result.get("tags", [])
    #     flattened_tags = [tag for group in tags for tag in (group if isinstance(group, list) else [group])]

    #     techniques_raw = analysis_result.get("attack_techniques", [])
    #     formatted_techniques = []

    #     for entry in techniques_raw:
    #         if isinstance(entry, dict):
    #             # Already a single dict
    #             display = entry.get("display_name") or f"{entry.get('id', '')} - {entry.get('name', '')}"
    #             formatted_techniques.append(display)
    #         elif isinstance(entry, list):
    #             # List of dicts
    #             for item in entry:
    #                 if isinstance(item, dict):
    #                     display = item.get("display_name") or f"{item.get('id', '')} - {item.get('name', '')}"
    #                     formatted_techniques.append(display)

        
    #     return {
    #             "ioc_value": ioc_request.ioc,
    #             "ioc_type": ioc_request.ioc_type,
    #             "name": analysis_result.get("name", []),
    #             "description": analysis_result.get("description", []),
    #             "references": references_str,
    #             "targeted_countries": flat_countries,
    #             "severity": analysis_result.get("severity", ThreatSeverity.LOW),
    #             "confidence_score": analysis_result.get("confidence_score", 0.0),
    #             "sources": sources,
    #             "additional_info":analysis_result.get("additional_info", []),
    #             "related_iocs": analysis_result.get("related_iocs", []),
    #             "threat_actors": analysis_result.get("threat_actors", []),
    #             "malware_signatures": analysis_result.get("malware_signatures", []),
    #             "attack_techniques": formatted_techniques,
    #             "tags": flattened_tags,

    #             "geographic_info": analysis_result.get("geographic_info", {}),
    #             "reputation_score": analysis_result.get("reputation_score", 0.0)
    #         }
    def _build_threat_context(self, ioc_request: IOCRequest, analysis_result: Dict[str, Any]):
        """Build ThreatContext from analysis results"""
        print("Made to threat context")

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

        # return {
        #     "ioc_value": ioc_request.ioc,
        #     "ioc_type": ioc_request.ioc_type,
        #     "name": flatten_list(analysis_result.get("name", [])),
        #     "description": flatten_list(analysis_result.get("description", [])),
        #     "references": references_str,
        #     "targeted_countries": flat_countries,
        #     "severity": analysis_result.get("severity", ThreatSeverity.LOW),
        #     "confidence_score": analysis_result.get("confidence_score", 0.0),
        #     "sources": sources,
        #     "additional_info": analysis_result.get("additional_info", []),
        #     "related_iocs": analysis_result.get("related_iocs", []),
        #     "threat_actors": flatten_list(analysis_result.get("threat_actors", [])),
        #     "malware_signatures": flatten_list(analysis_result.get("malware_signatures", [])),
        #     "attack_techniques": formatted_techniques,
        #     "tags": flattened_tags,
        #     "geographic_info": analysis_result.get("geographic_info", {}),
        #     "reputation_score": analysis_result.get("reputation_score", 0.0)
        # }
        result=json.dumps(analysis_result, indent=4)
        return result
