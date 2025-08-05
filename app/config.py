
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Database
    mongodb_url: str = Field(..., alias="MONGODB_URL")
    database_name: str = Field(..., alias="DATABASE_NAME")
    
    # JWT
    secret_key: str = Field(..., alias="SECRET_KEY")
    algorithm: str = Field(..., alias="ALGORITHM")
    access_token_expire_minutes: int = Field(..., alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_minutes: int = Field(..., alias="REFRESH_TOKEN_EXPIRE_MINUTES")
    
    # Security
    bcrypt_rounds: int = Field(..., alias="BCRYPT_ROUNDS")
    max_login_attempts: int = Field(..., alias="MAX_LOGIN_ATTEMPTS")
    lockout_duration_minutes: int = Field(..., alias="LOCKOUT_DURATION_MINUTES")

    # API Keys
    MZ_AUTH_KEY: str = Field(..., alias="MZ_AUTH_KEY")
    VT_AUTH_KEY: str = Field(..., alias="VT_AUTH_KEY")
    SHODAN_AUTH_KEY: str = Field(..., alias="SHODAN_AUTH_KEY")
    ALIEN_VAULT_KEY: str = Field(..., alias="ALIEN_VAULT_KEY")
    HA_AUTH_KEY: str = Field(..., alias="HA_AUTH_KEY")
    URLS_AUTH_KEY: str = Field(..., alias="URLS_AUTH_KEY")
    ABUSEIPDB_AUTH_KEY: str = Field(..., alias="ABUSEIPDB_AUTH_KEY")

    # Telegram
    TELEGRAM_API_ID: str = Field(..., alias="TELEGRAM_API_ID")
    TELEGRAM_API_HASH: str = Field(..., alias="TELEGRAM_API_HASH")
    TELEGRAM_PHONE: str = Field(..., alias="TELEGRAM_PHONE")

    # Token generation
    TOKEN_EXPIRY_HOURS: int = Field(..., alias="TOKEN_EXPIRY_HOURS")
    TOKEN_LENGTH: int = Field(..., alias="TOKEN_LENGTH")

    # Frontend & Email
    FRONTEND_URL: str = Field(..., alias="FRONTEND_URL")
    SMTP_SERVER: str = Field(..., alias="SMTP_SERVER")
    SMTP_PORT: int = Field(..., alias="SMTP_PORT")
    SMTP_USERNAME: str = Field(..., alias="SMTP_USERNAME")
    SMTP_PASSWORD: str = Field(..., alias="SMTP_PASSWORD")
    FROM_EMAIL: str = Field(..., alias="FROM_EMAIL")

    # GROQ
    GROQ_API_KEY: str = Field(..., alias="GROQ_API_KEY")
    GROQ_API_URL: str = Field(..., alias="GROQ_API_URL")
    MODEL: str = Field(..., alias="MODEL")
    
    # WebSocket
    WEBSOCKET_HOST: str = Field(..., alias="WEBSOCKET_HOST")
    WEBSOCKET_PORT: int = Field(..., alias="WEBSOCKET_PORT")

    class Config:
        env_file = ".env"
        validate_by_name = True

settings = Settings()