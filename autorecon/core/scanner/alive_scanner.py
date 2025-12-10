import httpx
import socket
from enum import Enum
from typing import List, Dict, Any
import time
import pathlib

class AliveLevel(str, Enum):
    STRONG = "strong"
    WEAK = "weak"
    DNS_ONLY = "dns_only"
    DEAD = "dead"

def ClassifyResult(alive: bool, status: int | None, reason: str | None) -> AliveLevel:
    if not alive:
        if reason == "DNS failed":
            return AliveLevel.DEAD
        if reason == "HTTP unreacheable":
            return AliveLevel.DNS_ONLY
        return AliveLevel.DEAD
    
    if status == None:
        return AliveLevel.DNS_ONLY
    
    if 200 <= status <= 399:
        return AliveLevel.STRONG
    
    if 400 <= status <= 599:
        return AliveLevel.WEAK
    
    return AliveLevel.WEAK


BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent 
print(BASE_DIR)
DATA_FILE = BASE_DIR / "data" / "subdomain_wordlist.txt"
with open(DATA_FILE, "r", encoding="utf-8") as f:
    WORDLIST = [line.strip() for line in f if line.strip()]

class AliveScanner:
    def __init__(self, target: str):
        self.target = target

    def resolve(self, host: str):
        if not host or host.startswith(".") or ".." in host:
            return False
        try:
            socket.gethostbyname(host)
            return True
        except socket.gaierror:
            return False
        
    def check_http(self, host: str):
        urls = [f"https://{host}", f"http://{host}"]
        for url in urls:
            try: 
                r = httpx.get(url, timeout=3)
                return url, r.status_code
            except Exception:
                continue
        return None, None
    
    def scan(self) -> List[Dict[str, Any]]:
        start_time = time.perf_counter()
        results = []
        for sub in WORDLIST:
            host = f"{sub}.{self.target}"

            if not self.resolve(host):
                alive = False
                status = None
                reason = "DNS failed"
                level = ClassifyResult(alive, status, reason)
                results.append({
                    "host": host,
                    "alive": alive,
                    "status": status,
                    "reason": reason,
                    "level": level
                })
                continue

            url, status = self.check_http(host)

            if url:
                alive = True
                reason = None
            else:
                alive = False
                reason = "HTTP unreacheable"

            level = ClassifyResult(alive, status, reason) 

            results.append({
                    "host": host,
                    "alive": alive,
                    "url": url,
                    "status": status,
                    "reason": reason,
                    "level": level
                })

        duration = time.perf_counter() - start_time
        self.duration = duration 
        return results