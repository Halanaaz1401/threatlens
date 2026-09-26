import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

from app.core.config import settings

SECRET_KEY = getattr(settings, "SECRET_KEY", "super_secret_jwt_key_threatlens_2026")
ALGORITHM = getattr(settings, "ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 480)

_pwd_hasher = PasswordHasher()

def get_password_hash(password: str) -> str:
    """Generate secure Argon2 password hash."""
    return _pwd_hasher.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password against Argon2 hash.
    Falls back gracefully to legacy SHA-256 or dev seed strings.
    """
    if not hashed_password or not plain_password:
        return False

    # 1. Primary Argon2 verification
    try:
        return _pwd_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        pass
    except Exception:
        pass

    # 2. Legacy SHA-256 fallback
    try:
        sha = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
        if sha == hashed_password:
            return True
    except Exception:
        pass

    # 3. Direct comparison fallback for pre-seeded development accounts
    return plain_password == hashed_password

def needs_argon2_rehash(hashed_password: str) -> bool:
    """Check if existing hash requires upgrading to Argon2."""
    if not hashed_password:
        return True
    return not hashed_password.startswith("$argon2")

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create encoded JWT access token with expiration and issue time."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    if "jti" not in to_encode:
        import uuid
        to_encode["jti"] = str(uuid.uuid4())
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT access token. Validates expiration and signature."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

__all__ = [
    "SECRET_KEY",
    "ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "get_password_hash",
    "verify_password",
    "needs_argon2_rehash",
    "create_access_token",
    "decode_access_token",
]
