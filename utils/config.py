from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    env: str = "dev"
    db_url: str = "mongodb://localhost:27017"
    db_name: str = "autorecon"
    log_level: str = "INFO"

    class Config:
        env_prefix = "AUTORECON_"
        env_file = ".env"

settings = Settings()