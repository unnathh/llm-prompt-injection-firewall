from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import os

from app.database.connection import get_db
from app.models.database import FirewallConfigOverride
from app.utils.auth import get_current_user_html

# Setup Jinja2 templates pointing to app/templates
templates = Jinja2Templates(directory="app/templates")

router = APIRouter(prefix="/dashboard", tags=["Dashboard Pages"])

@router.get("", response_class=HTMLResponse)
async def get_dashboard(request: Request, db: Session = Depends(get_db)) -> Response:
    user = get_current_user_html(request, db)
    if not user:
        return RedirectResponse(url="/dashboard/login")
        
    config = db.query(FirewallConfigOverride).filter_by(id=1).first()
    return templates.TemplateResponse(
        request=request,
        name="index.html", 
        context={"config": config}
    )

@router.get("/settings", response_class=HTMLResponse)
async def get_settings(request: Request, db: Session = Depends(get_db)) -> Response:
    user = get_current_user_html(request, db)
    if not user:
        return RedirectResponse(url="/dashboard/login")
        
    config = db.query(FirewallConfigOverride).filter_by(id=1).first()
    return templates.TemplateResponse(
        request=request,
        name="settings.html", 
        context={"config": config}
    )

@router.get("/test", response_class=HTMLResponse)
async def get_test(request: Request, db: Session = Depends(get_db)) -> Response:
    user = get_current_user_html(request, db)
    if not user:
        return RedirectResponse(url="/dashboard/login")
    return templates.TemplateResponse(request=request, name="test.html")

@router.get("/login", response_class=HTMLResponse)
async def get_login(request: Request, db: Session = Depends(get_db)) -> Response:
    user = get_current_user_html(request, db)
    if user:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})

@router.get("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse(url="/dashboard/login")
    response.delete_cookie("dashboard_session")
    return response

