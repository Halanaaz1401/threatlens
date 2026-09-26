from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.session import get_db
from app.models.user import User, UserRole
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    needs_argon2_rehash,
)
from app.core.rbac import get_current_user, require_admin, normalize_role
from app.services.audit_service import log_action

router = APIRouter()

class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str
    role: Optional[str] = "viewer"

class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

class UserResponse(BaseModel):
    id: str
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    role: str
    is_active: bool

class RoleUpdatePayload(BaseModel):
    role: str

@router.post("/register")
def register(user_in: UserRegister, request: Request, db: Session = Depends(get_db)):
    """
    Public self-registration.
    Strictly forbids self-assigning administrative or privileged roles.
    Defaults to 'viewer' role server-side.
    """
    # Reject privileged role escalation attempts
    if user_in.role:
        norm_role = normalize_role(user_in.role)
        if norm_role in ["admin", "security_engineer"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Client cannot assign privileged roles during self-registration"
            )

    # Check for duplicate user
    existing_user = db.query(User).filter(
        (User.email == user_in.email) | (User.username == user_in.email.split("@")[0])
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email or username already registered")

    safe_role = "viewer"
    if user_in.role and normalize_role(user_in.role) == "analyst":
        safe_role = "analyst"

    new_user = User(
        email=user_in.email,
        username=user_in.email.split("@")[0],
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=safe_role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Audit log registration
    log_action(
        db,
        action="USER_REGISTER",
        user_id=new_user.id,
        actor=new_user.email,
        target_resource="auth",
        details={"assigned_role": safe_role},
        request=request
    )

    return {"status": "success", "user_id": str(new_user.id), "role": safe_role}

@router.post("/login", response_model=Token)
def login(creds: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate user using Argon2, generate JWT, and log audit event.
    Re-hashes legacy passwords to Argon2 upon successful login.
    """
    identifier = creds.username or creds.email
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is required",
        )

    user = db.query(User).filter(
        (User.email == identifier) | (User.username == identifier)
    ).first()

    # Password verification
    if not user or not verify_password(creds.password, user.hashed_password):
        # Audit log failed login attempt
        log_action(
            db,
            action="FAILED_LOGIN_ATTEMPT",
            actor=identifier,
            target_resource="auth",
            details={"attempted_identifier": identifier},
            request=request
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    if not user.is_active:
        log_action(
            db,
            action="INACTIVE_LOGIN_ATTEMPT",
            actor=user.email,
            user_id=user.id,
            target_resource="auth",
            request=request
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    # Re-hash legacy passwords to Argon2
    if needs_argon2_rehash(user.hashed_password):
        user.hashed_password = get_password_hash(creds.password)
        db.commit()
        log_action(
            db,
            action="PASSWORD_HASH_UPGRADED_ARGON2",
            actor=user.email,
            user_id=user.id,
            target_resource="auth",
            request=request
        )

    user_role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    access_token = create_access_token(data={"sub": user.email, "role": user_role_str})

    # Audit log successful login
    log_action(
        db,
        action="USER_LOGIN",
        user_id=user.id,
        actor=user.email,
        target_resource="auth",
        request=request
    )

    return {"access_token": access_token, "token_type": "bearer", "role": user_role_str}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Retrieve identity and roles for the authenticated token bearer."""
    user_role_str = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "role": user_role_str,
        "is_active": current_user.is_active,
    }

@router.get("/users", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """Administrator-only: list all platform users."""
    users = db.query(User).all()
    return [
        {
            "id": str(u.id),
            "email": u.email,
            "username": u.username,
            "full_name": u.full_name,
            "role": u.role.value if hasattr(u.role, "value") else str(u.role),
            "is_active": u.is_active,
        }
        for u in users
    ]

@router.patch("/users/{user_id}/role")
def update_user_role(
    user_id: str,
    payload: RoleUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """Administrator-only: update user role and log authorization event."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = target_user.role
    target_user.role = normalize_role(payload.role)
    db.commit()
    db.refresh(target_user)

    log_action(
        db,
        action="USER_ROLE_UPDATED",
        actor=admin_user.email,
        user_id=target_user.id,
        target_resource=f"user:{user_id}",
        details={"old_role": old_role, "new_role": target_user.role},
        request=request
    )

    return {
        "status": "success",
        "user_id": str(target_user.id),
        "role": target_user.role
    }