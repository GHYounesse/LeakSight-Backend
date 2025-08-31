 
from app.database import db
import uuid



def generate_ioc_id() -> str:
        """Generate unique IOC ID"""
        return str(uuid.uuid4())
class EnrichmentCRUD:
    def __init__(self):
        
        
        if db.enrichment is None:
            raise RuntimeError("Enrichment collection not initialized")
        self.collection = db.enrichment
        
        
    
    