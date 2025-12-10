from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    env: str = "dev"
    db_url: Optional[str] = None
    db_name: str = "autorecon"
    db_password: Optional[str] = None
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_prefix = "AUTORECON_",
        env_file = ".env",
    )

settings = Settings()