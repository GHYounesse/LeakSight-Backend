
from fastapi import Body,APIRouter, Depends, HTTPException, Query, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
#from app.dependencies import get_current_user
from collections import defaultdict
from app.models import UserInDB
from app.api.auth import get_current_active_user
# Enums
class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    # EMAIL = "email"
    # REGISTRY_KEY = "registry_key"
    # MUTEX = "mutex"
    # USER_AGENT = "user_agent"

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

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

class IOCBulkCreate(BaseModel):
    iocs: List[IOCCreate] = Field(..., description="List of IOCs to create")

class IOCBulkResponse(BaseModel):
    created: List[IOCResponse] = Field(..., description="Successfully created IOCs")
    failed: List[Dict[str, Any]] = Field(..., description="Failed IOC creations with errors")
    summary: Dict[str, int] = Field(..., description="Summary statistics")

class IOCListResponse(BaseModel):
    iocs: List[IOCResponse]
    total: int
    page: int
    per_page: int
    pages: int

class TagRequest(BaseModel):
    tags: List[str] = Field(..., description="Tags to add to the IOC")

class RelatedIOCResponse(BaseModel):
    related_iocs: List[IOCResponse]
    relationship_type: str
    confidence: float


class FailedIOC(BaseModel):
    index: int
    ioc: IOCCreate  # or IOCCreate
    error: str
# In-memory storage (replace with database in production)
ioc_storage: Dict[str, IOCResponse] = {}

# Helper functions
# def get_current_user() -> str:
#     """Mock function to get current user - replace with actual authentication"""
#     return "system_user"



def find_related_iocs(ioc: IOCResponse) -> List[IOCResponse]:
    """Find related IOCs based on various criteria"""
    related = []
    
    for stored_ioc in ioc_storage.values():
        if stored_ioc.id == ioc.id:
            continue
            
        # Check for same source
        if ioc.source and stored_ioc.source == ioc.source:
            related.append(stored_ioc)
            continue
            
        # Check for common tags
        if set(ioc.tags) & set(stored_ioc.tags):
            related.append(stored_ioc)
            continue
            
        # Check for same type and similar metadata
        if (ioc.type == stored_ioc.type and 
            ioc.metadata and stored_ioc.metadata and
            set(ioc.metadata.keys()) & set(stored_ioc.metadata.keys())):
            related.append(stored_ioc)
    
    return related[:10]  # Limit to 10 related IOCs



# IOC Management Endpoints


ioc_router = APIRouter(prefix="/api/v1/iocs", tags=["IOC Management"])

from app.crud.ioc_crud import IOCCRUD

@ioc_router.post("/", response_model=IOCResponse, status_code=201)
async def create_ioc(ioc: IOCCreate,
    current_user: UserInDB = Depends(get_current_active_user)):
    """Create a single IOC"""
    
    user_id=current_user.id
    # Create IOC
    ioc_crud= IOCCRUD()
    try:
        ioc = await ioc_crud.create_ioc(ioc,user_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    return ioc

# @ioc_router.post("/bulk")
# async def bulk_create_iocs(bulk_request: Dict[str, Any] = Body(...),
#     current_user: UserInDB = Depends(get_current_active_user)):
#     """Bulk IOC upload"""
#     #print(bulk_request)
#     created = []
#     failed = []
#     ioc_crud=  IOCCRUD()
#     try:
#         failed,created= await ioc_crud.create_ioc_bulk(bulk_request,current_user)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
    
#     summary = {
#         "total_submitted": len(bulk_request["iocs"]),
#         "created": len(created),
#         "failed": len(failed)
#     }
    
#     return {
#         "created":created,
#         "failed":failed,
#         "summary":summary
#     }


@ioc_router.post("/bulk")
async def bulk_create_iocs(
    bulk_request: Dict[str, Any] = Body(...),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Bulk IOC upload"""
    ioc_crud = IOCCRUD()
    try:
        created, failed = await ioc_crud.create_ioc_bulk(bulk_request, current_user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    summary = {
        "total_submitted": len(bulk_request["iocs"]),
        "created": len(created),
        "failed": len(failed)
    }
    print({
        "created": created,
        "failed": failed,
        "summary": summary
    })
    return {
        "created": created,
        "failed": failed,
        "summary": summary
    }

@ioc_router.get("/")
async def list_iocs(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=1000, description="Items per page"),
    type: Optional[IOCType] = Query(None, description="Filter by IOC type"),
    threat_level: Optional[ThreatLevel] = Query(None, description="Filter by threat level"),
    status: Optional[IOCStatus] = Query(None, description="Filter by status"),
    source: Optional[str] = Query(None, description="Filter by source"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    search: Optional[str] = Query(None, description="Search in IOC values and descriptions"),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """List IOCs with filters"""
    ioc_crud= IOCCRUD()
    # Apply filters
    filtered_iocs = await ioc_crud.get_filtered_iocs(type, threat_level, status, source, tag, search) 
    
    # Sort by created_at (newest first)
    
    # Pagination
    total = len(filtered_iocs)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_iocs = filtered_iocs[start:end]
    
    pages = (total + per_page - 1) // per_page
    
    return IOCListResponse(
        iocs=paginated_iocs,
        total=total,
        page=page,
        per_page=per_page,
        pages=pages
    )

@ioc_router.get("/{ioc_id}")
async def get_ioc(ioc_id: str = Path(..., description="IOC identifier"),
    current_user: UserInDB = Depends(get_current_active_user)):
    """Get specific IOC"""
    ioc_crud= IOCCRUD()
    ioc= await ioc_crud.get_ioc_by_id(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    return ioc

@ioc_router.put("/{ioc_id}")
async def update_ioc(
    ioc_update: IOCUpdate,
    ioc_id: str = Path(..., description="IOC identifier"),
    current_user: UserInDB = Depends(get_current_active_user)
):
    """Update IOC"""
    ioc_crud= IOCCRUD()
    ioc= await ioc_crud.get_ioc_by_id(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    
    # Check for duplicate if value or type is being updated
    if ioc_update.value or ioc_update.type:
        new_value = ioc_update.value or ioc.value
        new_type = ioc_update.type or ioc.type
        
        await ioc_crud.check_duplicate_ioc(ioc_id, new_value, new_type)
        
    user_id=current_user.id
    existing_ioc= await ioc_crud.update_ioc(ioc_id,ioc_update,user_id)
    # Update fields
    return existing_ioc

@ioc_router.delete("/{ioc_id}", status_code=204)
async def delete_ioc(ioc_id: str = Path(..., description="IOC identifier"),
    current_user: UserInDB = Depends(get_current_active_user)):
    """Delete IOC"""
    ioc_crud= IOCCRUD()
    deleted = await ioc_crud.delete_ioc_by_id(ioc_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="IOC not found")
    
    
    return JSONResponse(status_code=204, content=None)

# @ioc_router.get("/{ioc_id}/related", response_model=RelatedIOCResponse)
# async def get_related_iocs(ioc_id: str = Path(..., description="IOC identifier")):
#     """Get related IOCs"""
    
#     if ioc_id not in ioc_storage:
#         raise HTTPException(status_code=404, detail="IOC not found")
    
#     ioc = ioc_storage[ioc_id]
#     related_iocs = find_related_iocs(ioc)
    
#     return RelatedIOCResponse(
#         related_iocs=related_iocs,
#         relationship_type="similarity_based",
#         confidence=0.75
#     )

# @ioc_router.post("/{ioc_id}/tags", response_model=IOCResponse)
# async def add_tags_to_ioc(
#     tag_request: TagRequest,
#     ioc_id: str = Path(..., description="IOC identifier"),
#     current_user: str = Depends(get_current_user)
# ):
#     """Add tags to IOC"""
    
#     if ioc_id not in ioc_storage:
#         raise HTTPException(status_code=404, detail="IOC not found")
    
#     existing_ioc = ioc_storage[ioc_id]
    
#     # Add new tags (avoid duplicates)
#     current_tags = set(existing_ioc.tags)
#     new_tags = set(tag_request.tags)
#     updated_tags = list(current_tags | new_tags)
    
#     existing_ioc.tags = updated_tags
#     existing_ioc.updated_at = datetime.utcnow()
#     existing_ioc.updated_by = current_user
    
#     ioc_storage[ioc_id] = existing_ioc
#     return existing_ioc

# Health check endpoint
# @ioc_router.get("/api/v1/health")
# async def health_check():
#     """Health check endpoint"""
#     return {
#         "status": "healthy",
#         "timestamp": datetime.utcnow(),
#         "total_iocs": len(ioc_storage)
#     }

# Statistics endpoint
# @ioc_router.get("/stats")
# async def get_ioc_statistics():
#     """Get IOC statistics"""
    
#     if not ioc_storage:
#         return {
#             "total_iocs": 0,
#             "by_type": {},
#             "by_threat_level": {},
#             "by_status": {}
#         }
    
#     stats = {
#         "total_iocs": len(ioc_storage),
#         "by_type": defaultdict(int),
#         "by_threat_level": defaultdict(int),
#         "by_status": defaultdict(int)
#     }
    
#     for ioc in ioc_storage.values():
#         stats["by_type"][ioc.type] += 1
#         stats["by_threat_level"][ioc.threat_level] += 1
#         stats["by_status"][ioc.status] += 1
    
#     return {
#         "total_iocs": stats["total_iocs"],
#         "by_type": dict(stats["by_type"]),
#         "by_threat_level": dict(stats["by_threat_level"]),
#         "by_status": dict(stats["by_status"])
#     }
