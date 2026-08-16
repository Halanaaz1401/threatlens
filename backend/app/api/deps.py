from fastapi import HTTPException, status, Depends
from app.models.user import User
from app.core.security import get_current_user

def require_roles(allowed_roles: list[str]):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles and current_user.role != "Administrator":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error_code": "FORBIDDEN_ACTION",
                    "message": f"Role '{current_user.role}' lacks permission for this action.",
                    "correlation_id": "sec-rbac-denial"
                }
            )
        return current_user
    return role_checker