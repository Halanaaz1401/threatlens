from typing import List, Union, Optional
from fastapi import Depends, HTTPException, status, Query, WebSocket
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlalchemy.orm import Session

from app.core.redis import redis_manager
from app.db.session import get_db
from app.models.user import User, UserRole
from app.core.security import SECRET_KEY, ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=True)

def normalize_role(role_val: Union[str, UserRole]) -> str:
    """Normalize various role casing and synonyms into canonical permission strings."""
    if isinstance(role_val, UserRole):
        role_str = role_val.value
    else:
        role_str = str(role_val)
    role_str = role_str.strip().lower()

    if role_str in ["admin", "administrator"]:
        return "admin"
    if role_str in ["security_engineer", "security engineer"]:
        return "security_engineer"
    if role_str in ["analyst", "soc_analyst", "soc analyst", "incident_responder", "threat_hunter"]:
        return "analyst"
    if role_str in ["viewer", "guest"]:
        return "viewer"
    return role_str

# Role permission tier mappings
ROLE_TIERS = {
    "admin": ["admin", "security_engineer", "analyst", "viewer", "executive"],
    "security_engineer": ["security_engineer", "analyst", "viewer"],
    "analyst": ["analyst", "viewer"],
    "viewer": ["viewer"],
    "executive": ["executive", "viewer"],
}

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Authenticate request via JWT bearer token.
    Enforces expiration, signature validity, and active database user status.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    expired_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token has expired",
        headers={"WWW-Authenticate": "Bearer"},
    )

    revoked_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token has been revoked",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        subject: str = payload.get("sub")
        if subject is None:
            raise credentials_exception
        jti = payload.get("jti")
        if jti and redis_manager.is_token_revoked(jti):
            raise revoked_exception
    except jwt.ExpiredSignatureError:
        raise expired_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter((User.email == subject) | (User.username == subject)).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user

async def get_ws_current_user(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Authenticate WebSocket connection via JWT query parameter ?token=...
    or Authorization header. Closes with policy violation code (1008) on failure.
    """
    token_str = token
    if not token_str:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token_str = auth_header[7:]

    if not token_str:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing authentication token")
        return None

    try:
        payload = jwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
        subject = payload.get("sub")
        if not subject:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token claims")
            return None
        jti = payload.get("jti")
        if jti and redis_manager.is_token_revoked(jti):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Token has been revoked")
            return None
    except jwt.ExpiredSignatureError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Token has expired")
        return None
    except jwt.PyJWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token signature")
        return None

    user = db.query(User).filter((User.email == subject) | (User.username == subject)).first()
    if user is None or not user.is_active:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User inactive or not found")
        return None

    return user

class RoleChecker:
    """
    Enforces role-based access control.
    Administrators possess superset access across all protected resources.
    """
    def __init__(self, allowed_roles: List[Union[UserRole, str]]):
        self.allowed_roles = [normalize_role(r) for r in allowed_roles]

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        user_role = normalize_role(current_user.role)

        # Admin always allowed
        if user_role == "admin":
            return current_user

        # Direct match
        if user_role in self.allowed_roles:
            return current_user

        # Tiered capability match
        user_capabilities = ROLE_TIERS.get(user_role, [user_role])
        if any(allowed in user_capabilities for allowed in self.allowed_roles):
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Insufficient role permissions"
        )

# Predefined role dependencies
require_authenticated_user = get_current_user
require_viewer = RoleChecker(["viewer"])
require_analyst = RoleChecker(["analyst"])
require_engineer = RoleChecker(["security_engineer"])
require_admin = RoleChecker(["admin"])

__all__ = [
    "oauth2_scheme",
    "normalize_role",
    "get_current_user",
    "get_ws_current_user",
    "RoleChecker",
    "require_authenticated_user",
    "require_viewer",
    "require_analyst",
    "require_engineer",
    "require_admin",
]