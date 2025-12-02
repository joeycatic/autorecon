import click
from core.scanner.socket_port_scanner import PortLevel
from core.scanner.alive_scanner import AliveLevel
from typing import Dict, Any

def format_alive_result_line(r: Dict[str, Any]) -> str:
    host = r["host"]
    level = r["level"]
    status = r.get("status")
    reason = r.get("reason")

    if level == AliveLevel.STRONG.value:
        symbol = "[💚]"
        color = "green"
        detail = f"{status} (strong)"
    elif level == AliveLevel.WEAK.value:
        symbol = "[💛]"
        color = "yellow"
        detail = f"{status} (weak)"
    elif level == AliveLevel.DNS_ONLY.value:
        symbol = "[💙]"
        color = "blue"
        detail = "DNS only / no HTTP"
    else:  
        symbol = "[❌]"
        color = "red"
        detail = reason or "dead"

    text = f"{symbol} {host} → {detail}"
    return click.style(text, fg=color)

def format_port_result_line(r: Dict[str, Any]) -> str:
    host = r["host"]
    ip = r["ip"]
    port = r["port"]
    level = r["level"]

    if level == PortLevel.SAFE.value:
        symbol = "[💚]"
        color = "green"
        level = PortLevel.SAFE.value
    elif level == PortLevel.MEDIUM.value:
        symbol = "[💛]"
        color = "yellow"
        level = PortLevel.MEDIUM.value
    elif level == PortLevel.HIGH.value:
        symbol = "[🧡]"
        color = 214
        level = PortLevel.HIGH.value
    elif level == PortLevel.CRITICAL.value:
        symbol = "[❤️]"
        color = "red"
        level = PortLevel.CRITICAL.value
    elif level == PortLevel.WEB.value:
        symbol = "[💙]"
        color = "blue"
        level = PortLevel.WEB.value
    else:  
        symbol = "[❌]"
        color = "red"
        level = "Unreacheable"

    text = f"{symbol} {level} {port} → {ip}"

    return click.style(text=text, fg=color)