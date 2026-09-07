from app.core.config import get_settings, Settings


def test_settings_defaults():
    settings = Settings(
        POSTGRES_HOST="testhost",
        REDIS_HOST="testredis",
    )
    assert settings.app_name == "NETGUARD"
    assert settings.app_version == "0.1.0"
    assert settings.postgres_port == 5432
    assert settings.redis_port == 6379
    assert settings.backend_port == 8000


def test_database_url():
    settings = Settings(
        POSTGRES_HOST="dbhost",
        POSTGRES_PORT="5433",
        POSTGRES_DB="testdb",
        POSTGRES_USER="testuser",
        POSTGRES_PASSWORD="testpass",
    )
    url = settings.database_url
    assert "asyncpg" in url
    assert "dbhost" in url
    assert "5433" in url
    assert "testdb" in url


def test_database_url_sync():
    settings = Settings(
        POSTGRES_HOST="dbhost",
        POSTGRES_PORT="5433",
        POSTGRES_DB="testdb",
        POSTGRES_USER="testuser",
        POSTGRES_PASSWORD="testpass",
    )
    url = settings.database_url_sync
    assert "postgresql://" in url
    assert "asyncpg" not in url


def test_redis_url():
    settings = Settings(REDIS_HOST="redishost", REDIS_PORT="6380")
    url = settings.redis_url
    assert url == "redis://redishost:6380/0"


def test_settings_singleton():
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
