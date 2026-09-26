from typing import List, Union
from fastapi import HTTPException, status, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User, UserRole, Role
from app.core.rbac import (
    get_current_user,
    get_ws_current_user,
    RoleChecker,
    oauth2_scheme,
    require_authenticated_user,
    require_viewer,
    require_analyst,
    require_engineer,
    require_admin,
    normalize_role,
)

def require_roles(allowed_roles: List[Union[str, UserRole]]):
    """General dependency factory for custom role allowances."""
    return RoleChecker(allowed_roles)

__all__ = [
    "get_db",
    "get_current_user",
    "get_ws_current_user",
    "require_roles",
    "RoleChecker",
    "oauth2_scheme",
    "require_authenticated_user",
    "require_viewer",
    "require_analyst",
    "require_engineer",
    "require_admin",
    "normalize_role",
    "User",
    "UserRole",
    "Role",
]