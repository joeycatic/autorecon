from .db import get_db

def save_open_port_results(results: list):
    db = get_db()
    col = db["open_ports"]

    if not results:
        print("[storage] No open ports to save — skipping insert_many().")
        return
    
    col.insert_many(results)