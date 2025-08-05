from pydantic import BaseModel,EmailStr
from typing import Optional

class Message(BaseModel):
    message: str
    status: str = "success"
    

class Token(BaseModel):
    username:str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenData(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None
    

