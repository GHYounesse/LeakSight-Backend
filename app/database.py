from pymongo import MongoClient

# client = MongoClient("mongodb://localhost:27017/")
# db = client["threat_intel"]




# iocs=db["iocs"]
# feeds_col = db["feeds"]

# users = db["users"]


from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import IndexModel, ASCENDING
from app.config import settings

class Database:
    def __init__(self):
        
        self.client: AsyncIOMotorClient = None
        self.database = None
        self.users_col = None
        
        
        
        self.iocs = None
        self.feeds = None
        
        self.password_reset_tokens_col = None
        
        self.enrichment = None   
        self.analysis_jobs = None
        
        self.scoring_jobs = None
        self.score_history  = None
        self.scoring_weights = None
        self.weight_changes = None
        
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
    db.analysis_jobs = db.database["analysis_jobs"]
    
    
    db.scoring_jobs = db.database["scoring_jobs"]
    db.score_history  = db.database["score_history "]   
    db.scoring_weights = db.database["scoring_weights"]
    db.weight_changes = db.database["weight_changes"]
    
    db.subscriptions = db.database["subscriptions"]
    db.messages = db.database["messages"]
    db.alerts = db.database["alerts"]
    


    await create_indexes()
    print("✅ Connected to MongoDB")

async def close_mongo_connection():
    if db.client:
        db.client.close()
        print("🔌 Disconnected from MongoDB")

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
