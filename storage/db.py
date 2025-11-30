from functools import lru_cache
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from utils.config import settings


@lru_cache
def get_client() -> MongoClient:
    client = MongoClient(settings.db_url)
    return client


def get_db():
    client = get_client()
    return client[settings.db_name]


def db_healthcheck() -> bool:

    try:
        db = get_db()
        db.command("ping")
        return True
    except ConnectionFailure:
        return False
