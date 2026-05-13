"""
AetherGuard Sentinel — Database Abstraction Layer
Tries MongoDB first; automatically falls back to TinyDB if unavailable.
"""
import logging
import os
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

USE_MONGO = False
_mongo_db = None
_tinydb_instance = None


async def init_mongodb() -> bool:
    global USE_MONGO, _mongo_db
    try:
        import motor.motor_asyncio
        from config.settings import settings
        client = motor.motor_asyncio.AsyncIOMotorClient(
            settings.MONGODB_URL,
            serverSelectionTimeoutMS=3000
        )
        await client.server_info()
        _mongo_db = client[settings.MONGODB_DB]
        USE_MONGO = True
        logger.info("✅ MongoDB connected successfully")
        return True
    except Exception as exc:
        logger.warning(f"⚠️  MongoDB unavailable ({exc}). Using TinyDB fallback.")
        USE_MONGO = False
        return False


def init_tinydb():
    global _tinydb_instance
    from tinydb import TinyDB
    os.makedirs("data", exist_ok=True)
    _tinydb_instance = TinyDB("data/aetherguard.json")
    logger.info("✅ TinyDB initialised at data/aetherguard.json")


def _get_tinydb_table(name: str):
    return _tinydb_instance.table(name)


def _tinydb_match(doc: dict, query: dict) -> bool:
    """Simple equality + operator matching for TinyDB."""
    for k, v in query.items():
        if isinstance(v, dict):
            dv = doc.get(k)
            for op, val in v.items():
                if op == "$gte" and not (dv is not None and dv >= val):
                    return False
                elif op == "$lte" and not (dv is not None and dv <= val):
                    return False
                elif op == "$gt" and not (dv is not None and dv > val):
                    return False
                elif op == "$in" and dv not in val:
                    return False
                elif op == "$ne" and dv == val:
                    return False
        elif isinstance(v, list):
            if doc.get(k) not in v:
                return False
        else:
            if doc.get(k) != v:
                return False
    return True


async def db_insert(collection: str, document: dict) -> str:
    doc = document.copy()
    if "_id" not in doc:
        doc["_id"] = str(uuid.uuid4())
    if "created_at" not in doc:
        doc["created_at"] = datetime.utcnow().isoformat()

    if USE_MONGO:
        await _mongo_db[collection].insert_one(doc)
    else:
        _get_tinydb_table(collection).insert(doc)
    return doc["_id"]


async def db_find(
    collection: str,
    query: dict = None,
    limit: int = 100,
    skip: int = 0,
    sort_field: str = "created_at",
    sort_desc: bool = True,
) -> List[dict]:
    if USE_MONGO:
        cursor = (
            _mongo_db[collection]
            .find(query or {}, {"_id": 0})
            .skip(skip)
            .limit(limit)
            .sort(sort_field, -1 if sort_desc else 1)
        )
        return await cursor.to_list(length=limit)
    else:
        table = _get_tinydb_table(collection)
        docs = table.all()
        if query:
            docs = [d for d in docs if _tinydb_match(d, query)]
        try:
            docs.sort(key=lambda x: x.get(sort_field, ""), reverse=sort_desc)
        except Exception:
            pass
        return docs[skip : skip + limit]


async def db_find_one(collection: str, query: dict) -> Optional[dict]:
    results = await db_find(collection, query, limit=1)
    return results[0] if results else None


async def db_update_one(collection: str, query: dict, update: dict) -> bool:
    if USE_MONGO:
        result = await _mongo_db[collection].update_one(query, {"$set": update})
        return result.modified_count > 0
    else:
        table = _get_tinydb_table(collection)
        all_docs = table.all()
        for doc in all_docs:
            if _tinydb_match(doc, query):
                table.update(update, doc_ids=[doc.doc_id])
                return True
        return False


async def db_update_many(collection: str, query: dict, update: dict) -> int:
    if USE_MONGO:
        result = await _mongo_db[collection].update_many(query, {"$set": update})
        return result.modified_count
    else:
        table = _get_tinydb_table(collection)
        all_docs = table.all()
        count = 0
        for doc in all_docs:
            if _tinydb_match(doc, query):
                table.update(update, doc_ids=[doc.doc_id])
                count += 1
        return count


async def db_delete(collection: str, query: dict) -> int:
    if USE_MONGO:
        result = await _mongo_db[collection].delete_many(query)
        return result.deleted_count
    else:
        from tinydb import Query as TQ
        table = _get_tinydb_table(collection)
        all_docs = table.all()
        ids = [d.doc_id for d in all_docs if _tinydb_match(d, query)]
        table.remove(doc_ids=ids)
        return len(ids)


async def db_count(collection: str, query: dict = None) -> int:
    if USE_MONGO:
        return await _mongo_db[collection].count_documents(query or {})
    else:
        docs = await db_find(collection, query, limit=100_000)
        return len(docs)


async def db_aggregate_severity(collection: str) -> dict:
    """Group by severity and return counts."""
    if USE_MONGO:
        pipeline = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
        cursor = _mongo_db[collection].aggregate(pipeline)
        results = await cursor.to_list(length=100)
        return {r["_id"]: r["count"] for r in results if r["_id"]}
    else:
        docs = await db_find(collection, limit=50_000)
        stats: dict = {}
        for d in docs:
            sev = d.get("severity", "info")
            stats[sev] = stats.get(sev, 0) + 1
        return stats
