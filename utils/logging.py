import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import settings

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger 

    logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    # Console
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File
    fh = RotatingFileHandler(LOG_DIR / "autorecon.log", maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger
