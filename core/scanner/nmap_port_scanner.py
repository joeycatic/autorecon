import nmap
import socket
import time

class NmapPortScanner:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()

    def fast_resolve(self):
        try:
            return socket.gethostbyname(self.target)
        except Exception as e:
            print(f"[DEBUG] DNS failed for {self.target}: {e}")
            return None

    def scan(self, start_port=1, end_port=1000, aggressive=False):
        start_time = time.perf_counter()
        if start_port > end_port:
            raise ValueError("start_port must be <= end_port")

        ip = self.fast_resolve()
        if not ip:
            return None

        if start_port is False or end_port is False:
            port_range = "1-1000"
        else:
            port_range = f"{start_port}-{end_port}"

        args = "-sV -T5" if aggressive else "-T5"
        out = self.nm.scan(ip, port_range, arguments=args)

        result = []        
        try:
            scan_data = list(out["scan"].values())[0]
            ports = scan_data.get("tcp", {})
        except Exception:
            return []

        for port, pdata in ports.items():
            result.append({
                "port": port,
                "state": pdata.get("state"),
                "service": pdata.get("name"),
                "version": pdata.get("version")
            })

        duration = time.perf_counter() - start_time
        self.duration = duration 
        return result
