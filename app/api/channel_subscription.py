import asyncio
from app.database import db
from datetime import datetime
from typing import List, Dict
from dataclasses import  asdict
from pymongo.errors import  DuplicateKeyError
from app.models.auth import *
from fastapi import APIRouter, Depends, HTTPException
from app.models import UserInDB
from app.dependencies import logger
from bson import ObjectId
from app.api.auth import get_current_active_user

subs_router = APIRouter(prefix="/auth", tags=["Authentication"])


async def subscribe_user_to_channel(user_id: str, channel_username: str, keywords: List[Dict]) -> bool:
    """Subscribe user to a channel with keywords (CREATE only)"""
    try:
        # Convert keyword dicts to UserKeyword objects
        user_keywords = [UserKeyword(**kw) for kw in keywords]
        
        subscription = UserChannelSubscription(
            user_id=user_id,
            channel_username=channel_username.replace('@', ''),
            keywords=user_keywords,
            created_at=datetime.utcnow()
        )
        
        loop = asyncio.get_event_loop()
        user_data = await db.users_col.find_one(
            {"_id": ObjectId(user_id)}
        )
        
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return False
            
        result=await db.subscriptions.insert_one(asdict(subscription))
        if result.inserted_id:
            logger.info(f"📺 User {user_id} subscribed to @{channel_username} with {len(keywords)} keywords")
            return True
        else:
            logger.warning(f"⚠️ Failed to add a subscription for {user_id} on @{channel_username}")
            return False
        
        
    except DuplicateKeyError:
        logger.error(f"❌ Subscription already exists for {user_id} on @{channel_username}")
        return False
    except Exception as e:
        logger.error(f"❌ Subscription error: {e}")
        return False

async def update_user_subscription(user_id: str, channel_username: str, keywords: List[Dict]) -> bool:
    """Update user's subscription keywords (UPDATE only)"""
    try:
        print("Made to the update func")
        user_keywords = [UserKeyword(**kw) for kw in keywords]
        
        loop = asyncio.get_event_loop()
        user_data = await db.users_col.find_one(
            {"_id": ObjectId(user_id)}
        )
        
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return False
            
        result = await  db.subscriptions.update_one(
            {"user_id": user_id, "channel_username": channel_username.replace('@', '')},
            {"$set": {"keywords": [asdict(kw) for kw in user_keywords], "updated_at": datetime.utcnow()}}
        )
        
        
        if result.modified_count > 0:
            logger.info(f"📝 Updated subscription for {user_id} on @{channel_username}")
            return True
        else:
            logger.warning(f"⚠️ No subscription found to update for {user_id} on @{channel_username}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Subscription update error: {e}")
        return False         

@subs_router.post("/subscribe", status_code=201)
async def create_subscription(request: SubscribeRequest, current_user: UserInDB = Depends(get_current_active_user)):
    """
    Create a new subscription to a Telegram channel with specific keywords.
    """
    success = await subscribe_user_to_channel(
        user_id=current_user.id,
        channel_username=request.channel_username,
        keywords=[kw.dict() for kw in request.keywords]
    )
    if not success:
        raise HTTPException(status_code=400, detail="Failed to create subscription or subscription already exists")
    return {"message": f"User {current_user.id} subscribed to @{request.channel_username}"}


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
        user_id=current_user.id,
        channel_username=channel_username,
        keywords=[kw.dict() for kw in request.keywords]
    )
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found or could not be updated")
    return {"message": f"Subscription updated for user {current_user.id} on @{channel_username}"}


async def delete_user_subscription(user_id: str, channel_username: str) -> bool:
    """Delete user's subscription to a channel"""
    try:
        loop = asyncio.get_event_loop()
        
        # Verify user exists
        user_data = await loop.run_in_executor(
            None,
            db.users_col.find_one,
            {"_id": user_id}
        )
        
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return False
            
        # Delete the subscription
        result = await loop.run_in_executor(
            None,
            db.subscriptions.delete_one,
            {"user_id": user_id, "channel_username": channel_username.replace('@', '')}
        )
        print("Result:",result)
        
        # if result.deleted_count > 0:
        #     logger.info(f"🗑️ Deleted subscription for {user_id} on @{channel_username}")
        return True
        # else:
        #     logger.warning(f"⚠️ No subscription found to delete for {user_id} on @{channel_username}")
        #     return False
            
    except Exception as e:
        logger.error(f"❌ Subscription deletion error: {e}")
        return False

@subs_router.delete("/subscriptions/{channel_username}", status_code=200)
async def delete_subscription(channel_username: str,current_user: UserInDB = Depends(get_current_active_user)):
    """
    Delete a user's subscription to a specific channel.
    """
    user_id=current_user.id
    success = await delete_user_subscription(user_id, channel_username)
    
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found or could not be deleted")
    
    return {"message": f"Subscription deleted for user {user_id} on @{channel_username}"}


@subs_router.put("/subscription/update", status_code=200)
async def update_subscription(request: SubscribeRequest,):
    """
    Update an existing subscription with new keywords.
    """
    success = await update_user_subscription(
        user_id=request.user_id,
        channel_username=request.channel_username,
        keywords=[kw.dict() for kw in request.keywords]
    )
    if not success:
        raise HTTPException(status_code=404, detail="No subscription found to update")
    return {"message": f"Subscription for {request.user_id} on @{request.channel_username} updated"}

@subs_router.get("/me/subscriptions", status_code=200)
async def get_subscriptions(current_user: UserInDB = Depends(get_current_active_user)):
    # Optional: validate ObjectId if you're using it
    # if not ObjectId.is_valid(user_id):
    #     raise HTTPException(status_code=400, detail="Invalid user ID format")
    user_id=current_user.id
    user_subs = await db.subscriptions.find({"user_id": user_id}).to_list(length=None)
    
    if not user_subs:
        raise HTTPException(status_code=404, detail="No subscriptions found for this user")
    
    # Optional: clean ObjectIds before returning
    for sub in user_subs:
        sub["_id"] = str(sub["_id"])
    
    return user_subs
