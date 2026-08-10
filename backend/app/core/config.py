from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    POSTGRES_USER: str = "threatlens_admin"
    POSTGRES_PASSWORD: str = "threatlens_secure_password_2026"
    POSTGRES_DB: str = "threatlens_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    
    SECRET_KEY: str = "super_secret_jwt_key_threatlens_2026"
    ALGORITHM: str = "HS256"
    
    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    class Config:
        env_file = ".env"

settings = Settings()
