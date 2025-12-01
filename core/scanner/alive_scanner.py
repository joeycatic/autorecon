import httpx
import socket

with open("subdomain_wordlist.txt", "r", encoding="utf-8") as f:
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
    
    def scan(self):
        results = []
        for sub in WORDLIST:
            host = f"{sub}.{self.target}"

            if not self.resolve(host):
                results.append({
                    "host": host,
                    "alive": False,
                    "reason": "DNS failed"
                })
                continue

            url, status = self.check_http(host)

            if url:
                results.append({
                    "host": host,
                    "alive": True,
                    "url": url,
                    "status": status
                })
            else:
                results.append({
                    "host": host,
                    "alive": False,
                    "reason": "HTTP unreachable"
                })

        return results