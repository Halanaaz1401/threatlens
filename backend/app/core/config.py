import os
from typing import List
from pydantic_settings import BaseSettings
from pydantic import ConfigDict

class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database Settings
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "threatlens_admin")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "threatlens_secure_password_2026")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "threatlens_db")
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))

    # Security & JWT Configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super_secret_jwt_key_threatlens_2026")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

    # Runtime Environment & CORS
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        raw = os.getenv("ALLOWED_ORIGINS")
        if raw:
            return [origin.strip() for origin in raw.split(",") if origin.strip()]
        return [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "https://threatlens.ashlynxcyber.in",
        ]

    # Redis Configuration
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_ALERT_CHANNEL: str = os.getenv("REDIS_ALERT_CHANNEL", "threatlens:events:alerts")
    REDIS_INCIDENT_CHANNEL: str = os.getenv("REDIS_INCIDENT_CHANNEL", "threatlens:events:incidents")
    REDIS_RULE_CHANNEL: str = os.getenv("REDIS_RULE_CHANNEL", "threatlens:events:rules")
    REDIS_IOC_CHANNEL: str = os.getenv("REDIS_IOC_CHANNEL", "threatlens:events:indicators")
    REDIS_FEED_CHANNEL: str = os.getenv("REDIS_FEED_CHANNEL", "threatlens:events:feeds")

    # Phase 4A Correlation Engine
    CORRELATION_WINDOW_MINUTES: int = int(os.getenv("CORRELATION_WINDOW_MINUTES", "15"))

    # Phase 4B Threat Intelligence Enrichment
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    THREAT_INTEL_CACHE_TTL_MINUTES: int = int(os.getenv("THREAT_INTEL_CACHE_TTL_MINUTES", "60"))
    REDIS_ENRICHMENT_CHANNEL: str = os.getenv("REDIS_ENRICHMENT_CHANNEL", "threatlens:events:enrichment")

    # Elasticsearch Configuration
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    ELASTICSEARCH_USERNAME: str = os.getenv("ELASTICSEARCH_USERNAME", "")
    ELASTICSEARCH_PASSWORD: str = os.getenv("ELASTICSEARCH_PASSWORD", "")
    ELASTICSEARCH_INDEX: str = os.getenv("ELASTICSEARCH_INDEX", "threatlens_indicators")

    @property
    def DATABASE_URL(self) -> str:
        explicit_url = os.getenv("DATABASE_URL")
        if explicit_url:
            return explicit_url
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

settings = Settings()
