from autorecon.storage.db import db_healthcheck, get_db

def healthcheck():
    ok = db_healthcheck()
    if not ok:
        return {"status": "error", "db": "unreachable"}

    db = get_db()
    db.health.insert_one({"check": "ok"})
    return {"status": "ok", "db": "connected"}
