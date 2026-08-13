from app.services.audit_service import log_action
from fastapi import Request
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from app.db.session import get_db
from app.models.user import User, UserRole
from app.core.security import verify_password, get_password_hash, create_access_token
from app.core.rbac import get_current_user

router = APIRouter()

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: UserRole = UserRole.SOC_ANALYST

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

@router.post("/register")
def register(user_in: UserRegister, request: Request, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=user_in.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # AUDIT LOG
    log_action(db, action="USER_REGISTER", user_id=new_user.id, request=request)

    return {"status": "success", "user_id": str(new_user.id), "role": new_user.role}

@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token = create_access_token(data={"sub": user.email, "role": user.role})

    # AUDIT LOG
    log_action(db, action="USER_LOGIN", user_id=user.id, request=request)

    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role
    }