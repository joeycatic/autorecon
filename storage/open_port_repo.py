from .db import get_db

def save_open_port_results(results: list):
    db = get_db()
    col = db["open_ports"]
    col.insert_many(results)