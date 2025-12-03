import socket
import time
import itertools
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
    def __init__(self, target, timeout=0.3, max_workers=800):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers

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
                result = s.connect_ex((ip, port))
                if result == 0:     # 0 = Verbindung erfolgreich
                    return port, ip
                return None
        except Exception:
            return None


    def scan(self, start_port=1, end_port=65535):
        start_time = time.perf_counter()
        host, ip = self.extract_ip()
        ports = range(start_port, end_port + 1)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for result in executor.map(self.scan_port, itertools.repeat(ip), ports):
                if result:
                    port, ip = result
                    level = self.set_profile(port)
                    self.result.append({
                        "host": host,
                        "ip": ip,
                        "port": port,
                        "level": level
                    })
        
        duration = time.perf_counter() - start_time
        self.duration = duration 
        return self.result   

    def fast_scan(self):
        start_time = time.perf_counter()
        host, ip = self.extract_ip()
        ports = set(
            self.PORT_LEVELS["safe"] +
            self.PORT_LEVELS["medium"] +
            self.PORT_LEVELS["high"] +
            self.PORT_LEVELS["critical"] +
            self.PORT_LEVELS["web"]
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for result in executor.map(self.scan_port, itertools.repeat(ip), ports):
                if result:
                    port, ip = result
                    level = self.set_profile(port)
                    self.result.append({
                        "host": host,
                        "ip": ip,
                        "port": port,
                        "level": level
                    })

        duration = time.perf_counter() - start_time
        self.duration = duration 
        return self.result
      