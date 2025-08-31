import asyncio
from app.crud.llama_rss_normalizer import periodic_process_feeds
from app.database import connect_to_mongo

async def main():
    await connect_to_mongo()  
    await periodic_process_feeds(1)

if __name__ == "__main__":
    asyncio.run(main())

