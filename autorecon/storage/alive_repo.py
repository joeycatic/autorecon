from .db import get_db

def save_alive_results(results: list):
    db = get_db()
    col = db["alive_hosts"]
    col.insert_many(results)

def save_dead_results(results: list):
    db = get_db()
    col = db["dead_hosts"]
    col.insert_many(results)