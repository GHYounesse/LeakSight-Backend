
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class IOCType(str, Enum):
    HASH = "hash"
    FILE_HASH = "hash"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    
    
IOC_TYPE_MAP = {
    "ip": IOCType.IP,
    "IPv4": IOCType.IP,
    "hostname": IOCType.DOMAIN,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "URI": IOCType.URL,
    "MD5": IOCType.HASH,
    "SHA1": IOCType.HASH,
    "SHA256": IOCType.HASH,
    "FileHash-SHA256": IOCType.HASH,
    "file_hash": IOCType.HASH,
}


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

class IOCStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    EXPIRED = "expired"

# Pydantic Models
class IOCBase(BaseModel):
    value: str = Field(..., description="The IOC value (IP, domain, hash, etc.)")
    type: IOCType = Field(..., description="Type of IOC")
    threat_level: ThreatLevel = Field(default=ThreatLevel.MEDIUM, description="Threat level")
    status: IOCStatus = Field(default=IOCStatus.ACTIVE, description="IOC status")
    description: Optional[str] = Field(None, description="Description of the IOC")
    source: Optional[str] = Field(None, description="Source of the IOC")
    confidence: int = Field(default=50, ge=0, le=100, description="Confidence level (0-100)")
    tags: List[str] = Field(default_factory=list, description="Tags associated with the IOC")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    expiration_date: Optional[datetime] = Field(None, description="When the IOC expires")

    @validator('value')
    def validate_value(cls, v):
        if not v or not v.strip():
            raise ValueError('IOC value cannot be empty')
        return v.strip()

class IOCCreate(IOCBase):
    pass

class IOCUpdate(BaseModel):
    value: Optional[str] = None
    type: Optional[IOCType] = None
    threat_level: Optional[ThreatLevel] = None
    status: Optional[IOCStatus] = None
    description: Optional[str] = None
    source: Optional[str] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    expiration_date: Optional[datetime] = None

class IOCResponse(IOCBase):
    id: str = Field(..., description="Unique IOC identifier")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    created_by: Optional[str] = Field(None, description="User who created the IOC")
    updated_by: Optional[str] = Field(None, description="User who last updated the IOC")



class IOCListResponse(BaseModel):
    iocs: List[IOCResponse]
    total: int
    page: int
    per_page: int
    pages: int





