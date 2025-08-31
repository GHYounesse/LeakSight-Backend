from pymongo import MongoClient
from app.dependencies import logger
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import IndexModel, ASCENDING
from app.config import settings

class Database:
    def __init__(self):
        
        self.client: AsyncIOMotorClient = None
        self.database = None
        self.users_col = None   
        self.pulses=None     
        self.iocs = None
        self.feeds = None
        self.password_reset_tokens_col = None
        self.enrichment = None   
        self.subscriptions = None
        self.messages = None
        self.alerts = None

db = Database()

async def connect_to_mongo():
    db.client = AsyncIOMotorClient(settings.mongodb_url)
    db.database = db.client[settings.database_name]
    
    db.users_col = db.database["users"]
    db.iocs = db.database["iocs"]
    db.feeds = db.database["feeds"]
    db.password_reset_tokens_col = db.database["password_reset_tokens"]
    db.enrichment = db.database["enrichment"]   
    db.subscriptions = db.database["subscriptions"]
    db.messages = db.database["messages"]
    db.alerts = db.database["alerts"]
    db.pulses= db.database["pulses"]
    


    await create_indexes()
    logger.info("✅ Connected to MongoDB")
    

async def close_mongo_connection():
    if db.client:
        db.client.close()
        logger.info("🔌 Disconnected from MongoDB")

async def create_indexes():
    indexes = [
        IndexModel([("email", ASCENDING)], unique=True),
        IndexModel([("username", ASCENDING)], unique=True),
        IndexModel([("created_at", ASCENDING)]),
        IndexModel([("last_login", ASCENDING)]),
    ]
    await db.users_col.create_indexes(indexes)
    await db.subscriptions.create_index(
        [("user_id", ASCENDING), ("channel_username", ASCENDING)],
        unique=True,
        name="user_channel_unique_idx"
    )

def get_database():
    if db.database is None:
        raise RuntimeError("Database not connected.")
    return db.database
