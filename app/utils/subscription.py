
from app.database import db
from datetime import datetime
from typing import List, Dict
from dataclasses import  asdict
from app.models.auth import *
from app.dependencies import logger
from bson import ObjectId


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
        
        user_data = await db.users_col.find_one(
            {"_id": ObjectId(user_id)}
        )
        
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return False
        
        # FIXED: Check for existing subscription first to avoid DuplicateKeyError
        existing = await db.subscriptions.find_one({
            "user_id": user_id,
            "channel_username": channel_username.replace('@', '')
        })
        
        if existing:
            logger.error(f"❌ Subscription already exists for {user_id} on @{channel_username}")
            return False
            
        result = await db.subscriptions.insert_one(asdict(subscription))
        if result.inserted_id:
            logger.info(f"📺 User {user_id} subscribed to @{channel_username} with {len(keywords)} keywords")
            return True
        else:
            logger.warning(f"⚠️ Failed to add a subscription for {user_id} on @{channel_username}")
            return False
        
    except Exception as e:
        logger.error(f"❌ Subscription error: {e}")
        return False


async def update_user_subscription(user_id: str, channel_username: str, keywords: List[Dict]) -> bool:
    """Update user's subscription keywords (UPDATE only)"""
    try:
        user_keywords = [UserKeyword(**kw) for kw in keywords]
        
        
        user_data = await db.users_col.find_one(
            {"_id": ObjectId(user_id)}
        )
        
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return False
            
        result = await db.subscriptions.update_one(
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

async def subscribe_user_to_multiple_channels(user_id: str, channel_usernames: List[str], keywords: List[Dict]) -> Dict[str, bool]:
    """Subscribe user to multiple channels with the same keywords"""
    try:
        # Check if user exists first
        user_data = await db.users_col.find_one({"_id": ObjectId(user_id)})
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return {channel: False for channel in channel_usernames}
        
        # Convert keyword dicts to UserKeyword objects
        user_keywords = [UserKeyword(**kw) for kw in keywords]
        
        results = {}
        successful_subscriptions = 0
        
        logger.info(f"🔄 Starting bulk subscription for user {user_id} to {len(channel_usernames)} channels")
        
        for channel_username in channel_usernames:
            try:
                clean_channel = channel_username.replace('@', '')
                
                # Check if subscription already exists
                existing = await db.subscriptions.find_one({
                    "user_id": user_id,
                    "channel_username": clean_channel
                })
                
                if existing:
                    logger.warning(f"⚠️ Subscription already exists for {user_id} on @{clean_channel}")
                    results[channel_username] = False
                    continue
                
                subscription = UserChannelSubscription(
                    user_id=user_id,
                    channel_username=clean_channel,
                    keywords=user_keywords,
                    created_at=datetime.utcnow()
                )
                
                result = await db.subscriptions.insert_one(asdict(subscription))
                
                if result.inserted_id:
                    results[channel_username] = True
                    successful_subscriptions += 1
                    logger.info(f"✅ Subscribed to @{clean_channel}")
                else:
                    results[channel_username] = False
                    logger.error(f"❌ Failed to subscribe to @{clean_channel}")
                    
            except Exception as e:
                logger.error(f"❌ Error subscribing to @{channel_username}: {e}")
                results[channel_username] = False
        
        logger.info(f"📊 Bulk subscription complete: {successful_subscriptions}/{len(channel_usernames)} successful")
        
        return results
        
    except Exception as e:
        logger.error(f"❌ Bulk subscription error: {e}")
        return {channel: False for channel in channel_usernames}

async def update_user_keywords_for_multiple_channels(user_id: str, channel_usernames: List[str], keywords: List[Dict]) -> Dict[str, bool]:
    """Update keywords for user across multiple channels"""
    try:
        # FIXED: Check if user exists first
        user_data = await db.users_col.find_one({"_id": ObjectId(user_id)})
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return {channel: False for channel in channel_usernames}
        
        user_keywords = [UserKeyword(**kw) for kw in keywords]
        
        results = {}
        successful_updates = 0
        
        logger.info(f"🔄 Updating keywords for user {user_id} across {len(channel_usernames)} channels")
        
        for channel_username in channel_usernames:
            try:
                clean_channel = channel_username.replace('@', '')
                
                filter_query = {
                    "user_id": user_id,
                    "channel_username": clean_channel
                }
                
                result = await db.subscriptions.update_one(
                    filter_query,
                    {
                        "$set": {
                            "keywords": [asdict(kw) for kw in user_keywords],  # FIXED: Consistent use of asdict
                            "updated_at": datetime.utcnow()
                        }
                    }
                )
                
                if result.modified_count > 0:
                    results[channel_username] = True
                    successful_updates += 1
                    logger.info(f"✅ Updated keywords for @{clean_channel}")
                elif result.matched_count > 0:
                    # Subscription exists but keywords were the same
                    results[channel_username] = True
                    logger.info(f"ℹ️ Keywords already up-to-date for @{clean_channel}")
                else:
                    results[channel_username] = False
                    logger.warning(f"⚠️ No subscription found for @{clean_channel}")
                    
            except Exception as e:
                logger.error(f"❌ Error updating @{channel_username}: {e}")
                results[channel_username] = False
        
        logger.info(f"📊 Keyword update complete: {successful_updates}/{len(channel_usernames)} successful")
        
        return results
        
    except Exception as e:
        logger.error(f"❌ Bulk keyword update error: {e}")
        return {channel: False for channel in channel_usernames}

async def unsubscribe_user_from_channels(user_id: str, channel_usernames: List[str]) -> Dict[str, bool]:
    """Unsubscribe user from multiple channels"""
    try:
        # FIXED: Check if user exists first
        user_data = await db.users_col.find_one({"_id": ObjectId(user_id)})
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return {channel: False for channel in channel_usernames}
        
        results = {}
        successful_unsubscribes = 0
        
        logger.info(f"🔄 Unsubscribing user {user_id} from {len(channel_usernames)} channels")
        
        for channel_username in channel_usernames:
            try:
                clean_channel = channel_username.replace('@', '')
                
                result = await db.subscriptions.delete_one({
                    "user_id": user_id,
                    "channel_username": clean_channel
                })
                
                if result.deleted_count > 0:
                    results[channel_username] = True
                    successful_unsubscribes += 1
                    logger.info(f"✅ Unsubscribed from @{clean_channel}")
                else:
                    results[channel_username] = False
                    logger.warning(f"⚠️ No subscription found for @{clean_channel}")
                    
            except Exception as e:
                logger.error(f"❌ Error unsubscribing from @{channel_username}: {e}")
                results[channel_username] = False
        
        logger.info(f"📊 Bulk unsubscribe complete: {successful_unsubscribes}/{len(channel_usernames)} successful")
        
        return results
        
    except Exception as e:
        logger.error(f"❌ Bulk unsubscribe error: {e}")
        return {channel: False for channel in channel_usernames}

async def delete_user_subscription(user_id: str, channel_username: str) -> bool:
    """Delete user's subscription to a channel"""
    try:
        # FIXED: Removed unnecessary loop and executor usage
        user_data = await db.users_col.find_one(
            {"_id": ObjectId(user_id)}
        )
        
        if not user_data:
            logger.error(f"❌ User not found: {user_id}")
            return False
            
        # Delete the subscription
        result = await db.subscriptions.delete_one({
            "user_id": user_id, 
            "channel_username": channel_username.replace('@', '')
        })
        
        if result.deleted_count > 0:
            logger.info(f"✅ Deleted subscription for {user_id} on @{channel_username}")
            return True
        else:
            logger.warning(f"⚠️ No subscription found to delete for {user_id} on @{channel_username}")
            return False
        
    except Exception as e:
        logger.error(f"❌ Subscription deletion error: {e}")
        return False


