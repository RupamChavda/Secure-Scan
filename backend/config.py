import os
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class Settings:
    PROJECT_NAME: str = "SecureScan AI"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "securescan-super-secret-jwt-key-2026-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 # 24 hours
    
    # AI Risk Integration Config
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY", "")
    DEFAULT_AI_MODEL: str = "gpt-4o-mini"
    
    # Storage & Upload Config
    UPLOAD_DIR: str = os.path.join(os.path.dirname(__file__), "uploads")
    REPORTS_DIR: str = os.path.join(os.path.dirname(__file__), "reports")

settings = Settings()

os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
