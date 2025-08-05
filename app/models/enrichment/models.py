from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class IOCType(str, Enum):
    HASH = "hash"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"

class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IOCRequest(BaseModel):
    ioc: str = Field(..., description="IOC value to analyze")
    ioc_type: IOCType = Field(..., description="Type of IOC")
    

class ThreatSource(BaseModel):
    name: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    last_seen: datetime
    tags: List[str] = []
    description: Optional[str] = None

class ThreatContext(BaseModel):
    ioc_value: str
    ioc_type: IOCType
    severity: ThreatSeverity
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    name: List[str] = []
    description:List[str] = []
    references:str
    tags:List[str] = []
    targeted_countries:List[str] = []
    sources: List[str] = []
    related_iocs: List[str] = []
    additional_info: List[str] = []
    threat_actors: List[str] = []
    malware_families: List[str] = []
    attack_techniques: List[str] = []
    geographic_info: Dict[str, Any] = {}
    reputation_score: float = Field(..., ge=0.0, le=100.0)
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)

class AnalysisResult(BaseModel):
    job_id: str
    status: str
    threat_context: Optional[ThreatContext] = None
    error_message: Optional[str] = None
    processing_time: Optional[float] = None
