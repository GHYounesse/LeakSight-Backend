from typing import Optional, List
from datetime import datetime, timedelta
from bson import ObjectId
from pymongo import ReturnDocument
from fastapi import HTTPException, status
from app.models import UserCreate, UserInDB, UserUpdate, UserResponse
from app.services import auth_service
from app.models.enums import UserStatus
from app.config import settings
  # Assuming users is the collection for user data
from app.database import db
class UserCRUD:
    def __init__(self):
        
        if db.users_col is None:
            raise RuntimeError("Users collection not initialized")
        self.collection = db.users_col
    
    async def create_user(self, user: UserCreate) -> UserInDB:
        """Create a new user"""
        # Check if user already exists
        
        existing_user = await self.collection.find_one({
            "$or": [
                {"email": user.email},
                {"username": user.username}
            ]
        })
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email or username already exists"
            )
        
        # Hash password
        hashed_password = auth_service.get_password_hash(user.password)
    
        # Create user document
        user_doc = {
            "email": user.email,
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
            "hashed_password": hashed_password,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login": None,
            "login_attempts": 0,
            "locked_until": None,
            "status": UserStatus.ACTIVE.value
        }
        print(user_doc)
        result = await self.collection.insert_one(user_doc)
        user_doc["id"] = str(result.inserted_id)
        
        return UserInDB(**user_doc)
    
    async def get_user_by_id(self, user_id: str) -> Optional[UserInDB]:
        """Get user by ID"""
        try:
            user_doc = await self.collection.find_one({"_id": ObjectId(user_id)})
            #print("UserDoc:",user_doc)
            if user_doc:
                user_doc["id"]=str(user_doc.pop("_id"))
                #del user_doc["_id"]
                #print("User 2 :",UserInDB(**user_doc))
                return UserInDB(**user_doc)
        except Exception:
            return None
        return None
    
    async def get_user_by_username(self, username: str) -> Optional[UserInDB]:
        """Get user by username"""
        user_doc = await self.collection.find_one({"username": username})
        
        if user_doc:
            user_doc["id"] = str(user_doc["_id"])  # Convert ObjectId to string
            del user_doc["_id"]  # Remove ObjectId field
            return UserInDB(**user_doc)
        return None
    
    
    
    async def get_user_by_email(self, email: str) -> Optional[UserInDB]:
        """Get user by email"""
        user_doc = await self.collection.find_one({"email": email})
        if user_doc:
            user_doc["id"] = str(user_doc["_id"])  # Convert ObjectId to string
            del user_doc["_id"]  # Remove ObjectId field
            return UserInDB(**user_doc)
        return None
    
    async def update_user(self, user_id: str, user_update: UserUpdate) -> Optional[UserInDB]:
        """Update user"""
        update_data = user_update.dict(exclude_unset=True)
        if not update_data:
            return await self.get_user_by_id(user_id)
        
        update_data["updated_at"] = datetime.utcnow()
        
        try:
            result = await self.collection.find_one_and_update(
                {"_id": ObjectId(user_id)},
                {"$set": update_data},
                return_document=ReturnDocument.AFTER
            )
            
            if result:
                return UserInDB(**result)
        except Exception:
            pass
        
        return None
    
    async def update_user_password(self, email: str, hashed_password: str) -> Optional[UserInDB]:
        """Update user password by email"""
        try:
            result = await self.collection.find_one_and_update(
                {"email": email},
                {"$set": {"hashed_password": hashed_password, "updated_at": datetime.utcnow()}},
                return_document=ReturnDocument.AFTER
            )
            
            if result:
                return UserInDB(**result)
        except Exception:
            pass
        
        return None
    
    async def delete_user(self, user_id: str) -> bool:
        """Delete user"""
        try:
            result = await self.collection.delete_one({"_id": ObjectId(user_id)})
            return result.deleted_count > 0
        except Exception:
            return False
    
    async def get_users(self, skip: int = 0, limit: int = 100) -> List[UserInDB]:
        """Get users with pagination"""
        cursor = self.collection.find().skip(skip).limit(limit)
        users = []
        async for user_doc in cursor:
            users.append(UserInDB(**user_doc))
        return users
    
    async def authenticate_user(self, email: str, password: str) -> Optional[UserInDB]:
        """Authenticate user"""
        print(f"Try Authenticating user - Email: {email}")
        user = await self.get_user_by_email(email)
        if not user:
            return None
        print(f"Authenticating user - ID {user.id}: {user.username}")

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked due to too many failed login attempts"
            )
        
        # Verify password
        if not auth_service.verify_password(password, user.hashed_password):
            # Increment login attempts
            await self.increment_login_attempts(user.id)
            return None
        
        # Reset login attempts on successful login
        await self.reset_login_attempts(user.id)
        await self.update_last_login(user.id)
        
        return user
    
    async def increment_login_attempts(self, user_id: str):
        """Increment login attempts and lock account if necessary"""
        try:
            user = await self.get_user_by_id(user_id)
            if not user:
                return
            
            new_attempts = user.login_attempts + 1
            update_data = {"login_attempts": new_attempts}
            
            # Lock account if max attempts reached
            if new_attempts >= settings.max_login_attempts:
                lockout_time = datetime.utcnow() + timedelta(minutes=settings.lockout_duration_minutes)
                update_data["locked_until"] = lockout_time
                update_data["status"] = UserStatus.LOCKED.value
            
            await self.collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": update_data}
            )
        except Exception:
            pass
    
    async def reset_login_attempts(self, user_id: str):
        """Reset login attempts"""
        try:
            await self.collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {
                    "login_attempts": 0,
                    "locked_until": None,
                    "status": UserStatus.ACTIVE.value
                }}
            )
        except Exception:
            pass
    
    async def update_last_login(self, user_id: str):
        """Update last login timestamp"""
        try:
            await self.collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"last_login": datetime.utcnow()}}
            )
        except Exception:
            pass