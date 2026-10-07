import logging
from typing import Optional
import pymongo
from pymongo import MongoClient
from pymongo.database import Database
from backend.config import settings

logger = logging.getLogger("securescan.db")

client: Optional[MongoClient] = None
db: Optional[Database] = None
_mongodb_available: bool = False

def init_db():
    global client, db, _mongodb_available
    try:
        client = MongoClient(settings.MONGODB_URL, serverSelectionTimeoutMS=2000)
        # Verify connection
        client.admin.command('ping')
        db = client[settings.MONGODB_DB_NAME]
        _mongodb_available = True
        logger.info(f"Connected successfully to MongoDB database '{settings.MONGODB_DB_NAME}' at {settings.MONGODB_URL}")
        print(f"[MongoDB] Successfully connected to MongoDB database '{settings.MONGODB_DB_NAME}'")
    except Exception as e:
        _mongodb_available = False
        client = None
        db = None
        logger.warning(f"MongoDB connection standard check failed: {e}. Falling back to persistent JSON storage.")
        print(f"[MongoDB] Warning: Could not connect to MongoDB server ({e}). Falling back to local file JSON storage.")

def get_db() -> Optional[Database]:
    global db, _mongodb_available
    if not _mongodb_available or db is None:
        init_db()
    return db if _mongodb_available else None

def is_mongodb_available() -> bool:
    global db, _mongodb_available
    if db is None:
        init_db()
    return _mongodb_available
