from fastapi import APIRouter, Depends, HTTPException, status,BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta,datetime
from app.models import UserCreate, UserInDB, LoginRequest, RefreshTokenRequest, Token,Message,ResetPasswordRequest,RequestResetPasswordRequest,ResetPasswordResponse
from app.crud import UserCRUD,ResetTokenCRUD
from app.config import settings
from app.services import auth_service
from app.database import get_database
from app.dependencies import logger
from jose import JWTError, jwt
from passlib.context import CryptContext

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])




security = HTTPBearer()




async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> UserInDB:
    """
    Dependency to get current authenticated user from JWT token
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        
        token = credentials.credentials
        
        # Decode JWT token
        payload = jwt.decode(
            token, 
            settings.secret_key, 
            algorithms=[settings.algorithm]
        )
        
        
        
        user_id: str = payload.get("sub")
        
        email: str = payload.get("email")
        
        if user_id is None or email is None:
            raise credentials_exception
            
    except JWTError as e:
        logger.error(f"JWT decode error: {e}")
        raise credentials_exception
    
    # Get user from database
    user_crud = UserCRUD()
    try:
        user = await user_crud.get_user_by_id(user_id)
        
        if user is None:
            raise credentials_exception
            
        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Inactive user"
            )
            
        return user
        
    except Exception as e:
        logger.error(f"Database error when getting user: {e}")
        raise credentials_exception

async def get_current_active_user(
    current_user: UserInDB = Depends(get_current_user)
) -> UserInDB:
    """
    Dependency to get current active user
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )
    return current_user

#Endpoint to register a new user

@auth_router.post("/register", response_model=Message, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    """Register a new user"""
    
    logger.info(f"Registering user: {user.username} with email: {user.email}")
    user_crud = UserCRUD()
    
    try:
        created_user = await user_crud.create_user(user)
        return Message(
            message="User created successfully",
            status="success"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in register route: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )

# Endpoint to login user and return access/refresh tokens
@auth_router.post("/login", response_model=Token)
async def login(login_data: LoginRequest):
    """Login user"""
    
    user_crud = UserCRUD()
    
    try:
        logger.info(f"Logging in user: {login_data.email}")
        user = await user_crud.authenticate_user(login_data.email, login_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        

        # Create tokens
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        refresh_token_expires = timedelta(minutes=settings.refresh_token_expire_minutes)
        access_token = auth_service.create_access_token(
            data={"sub": str(user.id), "email": user.email, "role": user.role},
            expires_delta=access_token_expires
        )
        
        refresh_token = auth_service.create_refresh_token(
            data={"sub": str(user.id), "email": user.email, "role": user.role},
            expires_delta=refresh_token_expires
        )
        logger.info(f"User authenticated successfully: {login_data.email}")
        return Token(
            username=user.username,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.access_token_expire_minutes * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in login route: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

# Endpoint to refresh access token using refresh token
@auth_router.post("/refresh", response_model=Token)
async def refresh_token(refresh_data: RefreshTokenRequest):
    """Refresh access token"""
    try:
        token_data = auth_service.verify_token(refresh_data.refresh_token, "refresh")
        
        # Verify user still exists and is active
        db = get_database()
        user_crud = UserCRUD(db)
        user = await user_crud.get_user_by_id(token_data.user_id)
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Create new tokens
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        refresh_token_expires = timedelta(minutes=settings.refresh_token_expire_minutes)
        
        access_token = auth_service.create_access_token(
            data={"sub": str(user.id), "username": user.username, "role": user.role},
            expires_delta=access_token_expires
        )
        
        new_refresh_token = auth_service.create_refresh_token(
            data={"sub": str(user.id), "username": user.username, "role": user.role},
            expires_delta=refresh_token_expires
        )
        
        return Token(
            username=user.username,
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=settings.access_token_expire_minutes * 60
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


# Endpoint to request password reset
@auth_router.post("/request_reset_password", response_model=ResetPasswordResponse)
async def request_reset_password(
    request: RequestResetPasswordRequest,
    background_tasks: BackgroundTasks
):
    """
    Request password reset - sends email if user exists
    Always returns success to prevent email enumeration
    """
    reset_token_crud = ResetTokenCRUD()
    user_crud = UserCRUD()
    try:
        # Check if user exists and is active
        user = await user_crud.get_user_by_email(request.email)
        
        
        if user:
            # Generate and store reset token
            token = await  reset_token_crud.create_reset_token(request.email)
            
            # Send reset email in background
            reset_token_crud.send_reset_email(request.email, token, background_tasks)

            return ResetPasswordResponse(
                message="If an account with this email exists, you will receive a password reset link shortly.",
                success=True
            )
        else:
            # Even if user doesn't exist, return success message
            # This prevents email enumeration attacks
            return ResetPasswordResponse(
                message="If an account with this email exists, you will receive a password reset link shortly.",
                success=True
            )
            
    except Exception as e:
        logger.error(f"Error in request_reset_password: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing your request. Please try again later."
        )

# Endpoint to reset user password using valid token
@auth_router.post("/reset_password")
async def reset_password(
    request: ResetPasswordRequest
):
    """
    Reset user password using valid token
    """
    token = request.token
    new_password = request.new_password
    reset_token_crud = ResetTokenCRUD()
    user_crud = UserCRUD()
    

        
    try:
        token_hash = reset_token_crud.hash_token(token)
        
        # Find valid token
        db_token = await reset_token_crud.password_reset_tokens_collection.find_one({
            "token_hash": token_hash,
            "used": False,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        if not db_token:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired token"
            )
        
        # Hash the new password (you should use proper password hashing)
        
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = pwd_context.hash(new_password)
        
        # Update user password
        await user_crud.update_user_password(db_token["email"], hashed_password)

        # Mark token as used
        await  reset_token_crud.password_reset_tokens_collection.update_one(
            {"_id": db_token["_id"]},
            {"$set": {"used": True}}
        )
        
        return {"message": "Password reset successfully", "success": True}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting password: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting password"
        )
        

