from utils.logging import get_logger

logger = get_logger(__name__)

def healthcheck():
    logger.info("Running healthcheck")
    return {"status": "ok"}
