from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Request, Depends, HTTPException, status
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from config.settings import settings
from app.database.connection import get_db
from app.models.database import DashboardUser

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generate a signed JSON Web Token (JWT) representing the user session.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT. Returns the payload dict if valid, else None.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user_api(request: Request, db: Session = Depends(get_db)) -> DashboardUser:
    """
    FastAPI dependency to secure dashboard REST API endpoints.
    Reads token from HttpOnly cookie and validates it.
    Raises 401 Unauthorized if invalid or expired.
    """
    token = request.cookies.get("dashboard_session")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session cookie missing. Not authenticated."
        )
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid or expired."
        )
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session payload is missing subject claim."
        )
    user = db.query(DashboardUser).filter_by(username=username, is_active=True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive."
        )
    return user

def get_current_user_html(request: Request, db: Session = Depends(get_db)) -> Optional[DashboardUser]:
    """
    Helper for HTML page routes. Returns the user if authenticated, otherwise None.
    Does not raise exception, allowing route handler to redirect.
    """
    token = request.cookies.get("dashboard_session")
    if not token:
        return None
    payload = verify_access_token(token)
    if not payload:
        return None
    username = payload.get("sub")
    if not username:
        return None
    try:
        user = db.query(DashboardUser).filter_by(username=username, is_active=True).first()
        return user
    except Exception:
        return None
