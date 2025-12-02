import socket
import re
from urllib.parse import urlparse
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

class PortLevel(str, Enum):
    SAFE = "safe"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    WEB = "web"

class SocketPortScanner():
    def __init__(self, target):
        self.target = target
        self.timeout = 0.3

        self.PORT_LEVELS = {
            "safe": [80, 443, 53, 123, 587, 25, 110, 143],
            "medium": [21, 22, 23, 445, 139, 3306, 1433, 1521, 27017, 6379],
            "high": [111, 389, 2049, 3389, 5900, 9200, 11211],
            "critical": [445, 2375, 5601, 5000, 8834],
            "web": [8080, 8000, 8443, 8888, 9090],
        }

        self.result = []

    def extract_ip(self):
        parsed = urlparse(self.target)
        host = parsed.hostname or self.target

        try:
            ip = socket.gethostbyname(host)
            return host, ip
        except socket.gaierror:
            return host, None

    def set_profile(self, port) -> PortLevel:
        if port in self.PORT_LEVELS["safe"]:
            return PortLevel.SAFE
        elif port in self.PORT_LEVELS["medium"]:
            return PortLevel.MEDIUM
        elif port in self.PORT_LEVELS["high"]:
            return PortLevel.HIGH
        elif port in self.PORT_LEVELS["critical"]:
            return PortLevel.CRITICAL
        elif port in self.PORT_LEVELS["web"]:
            return PortLevel.WEB
        else:
            return PortLevel.HIGH  
        
    def scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)

                s.connect((ip, port))
                return port, ip
        except:
            return None

    def scan(self):
        host, ip = self.extract_ip()
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.scan_port, ip, port) for port in range(1, 65536)]

        for f in futures:
            result = f.result()
            if result:
                port, ip = result
                level = self.set_profile(port)
                self.result.append({
                    "host": host,
                    "ip": ip,
                    "port": port,
                    "level": level
                })

        return self.result         