
from fastapi import Body,APIRouter, Depends, HTTPException, Query, Path
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
from app.models import UserInDB
from app.api.auth import get_current_active_user
from app.crud.ioc_crud import IOCCRUD
from app.models.ioc import *



# IOC Management Endpoints


ioc_router = APIRouter(prefix="/api/v1/iocs", tags=["IOC Management"])



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


