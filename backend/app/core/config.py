from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Application
    app_name: str = "NETGUARD"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True
    secret_key: str = "change-me-in-production"

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "netguard"
    postgres_user: str = "netguard"
    postgres_password: str = "netguard_secret_change_me"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379

    # Backend server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000

    # Packet Engine
    packet_engine_host: str = "localhost"
    packet_engine_port: int = 8001

    # ML
    ml_models_dir: str = "./ml/artifacts"

    # File upload
    max_upload_size_mb: int = 500

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url_sync(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/0"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
