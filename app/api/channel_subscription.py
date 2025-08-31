from app.database import db
from app.models.auth import *
from fastapi import APIRouter, Depends, HTTPException
from app.models import UserInDB
from app.api.auth import get_current_active_user
from app.utils.subscription import *

subs_router = APIRouter(prefix="/auth", tags=["Authentication"])





@subs_router.post("/subscribe", status_code=201)
async def create_subscription(request: SubscribeRequest, current_user: UserInDB = Depends(get_current_active_user)):
    """
    Create a new subscription to a Telegram channel with specific keywords.
    """
    success = await subscribe_user_to_channel(
        user_id=str(current_user.id),  # FIXED: Ensure string conversion
        channel_username=request.channel_username,
        keywords=[kw.dict() for kw in request.keywords]
    )
    if not success:
        raise HTTPException(status_code=400, detail="Failed to create subscription or subscription already exists")
    return {"message": f"User {current_user.id} subscribed to @{request.channel_username}"}

@subs_router.post("/bulk/subscribe", status_code=201)  # FIXED: Removed trailing slash for consistency
async def create_bulk_subscription(request: BulkSubscribeRequest, current_user: UserInDB = Depends(get_current_active_user)):
    """
    Create subscriptions to multiple Telegram channels with specific keywords.
    """
    results = await subscribe_user_to_multiple_channels(
        user_id=str(current_user.id),  # FIXED: Ensure string conversion
        channel_usernames=request.channel_usernames,
        keywords=[kw.dict() for kw in request.keywords]
    )
    
    # FIXED: Check results properly instead of just success boolean
    successful_count = sum(1 for success in results.values() if success)
    
    if successful_count == 0:
        raise HTTPException(status_code=400, detail="Failed to create any subscriptions")
    
    return {
        "message": f"User {current_user.id} subscribed to {successful_count}/{len(request.channel_usernames)} channels",
        "results": results,
        "successful_count": successful_count,
        "total_requested": len(request.channel_usernames)
    }

@subs_router.put("/subscriptions/{channel_username}", status_code=200)
async def update_subscription(
    channel_username: str, 
    request: SubscribeRequest, 
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Update an existing subscription's keywords for a specific channel.
    """
    success = await update_user_subscription(
        user_id=str(current_user.id),  # FIXED: Ensure string conversion
        channel_username=channel_username,
        keywords=[kw.dict() for kw in request.keywords]
    )
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found or could not be updated")
    return {"message": f"Subscription updated for user {current_user.id} on @{channel_username}"}

@subs_router.put("/bulk/subscriptions", status_code=200)  # FIXED: Removed trailing slash and changed to PUT
async def update_multiple_subscriptions(
    request: BulkSubscribeRequest,
    current_user: UserInDB = Depends(get_current_active_user)
):
    """
    Update keywords for multiple existing subscriptions.
    """
    results = await update_user_keywords_for_multiple_channels(
        user_id=str(current_user.id),  # FIXED: Ensure string conversion
        channel_usernames=request.channel_usernames,
        keywords=[kw.dict() for kw in request.keywords]
    )
    
    # FIXED: Check results properly
    successful_count = sum(1 for success in results.values() if success)
    
    if successful_count == 0:
        raise HTTPException(status_code=404, detail="No subscriptions found or could not be updated")
    
    return {
        "message": f"Updated {successful_count}/{len(request.channel_usernames)} subscriptions for user {current_user.id}",
        "results": results,
        "successful_count": successful_count,
        "total_requested": len(request.channel_usernames)
    }

@subs_router.delete("/subscriptions/{channel_username}", status_code=200)
async def delete_subscription(channel_username: str, current_user: UserInDB = Depends(get_current_active_user)):
    """
    Delete a user's subscription to a specific channel.
    """
    user_id = str(current_user.id)  # FIXED: Ensure string conversion
    success = await delete_user_subscription(user_id, channel_username)
    
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found or could not be deleted")
    
    return {"message": f"Subscription deleted for user {user_id} on @{channel_username}"}

@subs_router.delete("/bulk/subscriptions", status_code=200)  # FIXED: Removed trailing slash
async def delete_bulk_subscriptions(request: BulkUnsubscribeRequest, current_user: UserInDB = Depends(get_current_active_user)):
    """
    Delete a user's subscriptions to multiple channels.
    """
    user_id = str(current_user.id)  # FIXED: Ensure string conversion
    channel_usernames = request.channel_usernames

    results = await unsubscribe_user_from_channels(user_id, channel_usernames)

    # FIXED: Check results properly instead of just success boolean
    successful_count = sum(1 for success in results.values() if success)
    
    if successful_count == 0:
        raise HTTPException(status_code=404, detail="No subscriptions found or could not be deleted")

    return {
        "message": f"Deleted {successful_count}/{len(channel_usernames)} subscriptions for user {user_id}",
        "results": results,
        "successful_count": successful_count,
        "total_requested": len(channel_usernames)
    }
    
@subs_router.get("/me/subscriptions", status_code=200)
async def get_subscriptions(current_user: UserInDB = Depends(get_current_active_user)):
    
    user_id=current_user.id
    user_subs = await db.subscriptions.find({"user_id": user_id}).to_list(length=None)
    
    if not user_subs:
        raise HTTPException(status_code=404, detail="No subscriptions found for this user")
    
    # Optional: clean ObjectIds before returning
    for sub in user_subs:
        sub["_id"] = str(sub["_id"])
    
    return user_subs

