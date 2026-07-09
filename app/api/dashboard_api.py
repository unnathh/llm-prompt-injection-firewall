from fastapi import APIRouter, Depends, HTTPException, Request, Response, Form
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

import secrets
import hashlib
from app.database.connection import get_db, verify_password, hash_password
from app.models.database import FirewallLog, FirewallConfigOverride, DashboardUser, ApiKey
from app.scoring.engine import scoring_engine
from app.sanitization.sanitizers import sanitization_engine
from app.utils.auth import create_access_token, get_current_user_api

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard API"])

@router.post("/login")
async def api_login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
) -> Response:
    user = db.query(DashboardUser).filter_by(username=username, is_active=True).first()
    if not user or not verify_password(password, user.hashed_password):
        # Redirect back to login page with error query parameter
        return RedirectResponse(url="/dashboard/login?error=invalid_credentials", status_code=303)
        
    # Valid login: generate JWT access token, set cookie and redirect to dashboard
    access_token = create_access_token({"sub": username})
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="dashboard_session",
        value=access_token,
        httponly=True,
        max_age=3600,  # 1 hour
        samesite="lax"
    )
    return response

@router.get("/stats")
async def get_stats(
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> Dict[str, Any]:
    # Totals
    total = db.query(func.count(FirewallLog.id)).scalar() or 0
    blocked = db.query(func.count(FirewallLog.id)).filter(FirewallLog.action_taken == "block").scalar() or 0
    allowed = db.query(func.count(FirewallLog.id)).filter(FirewallLog.action_taken == "allow").scalar() or 0
    warned = db.query(func.count(FirewallLog.id)).filter(FirewallLog.action_taken == "warn").scalar() or 0
    sanitized = db.query(func.count(FirewallLog.id)).filter(FirewallLog.action_taken == "sanitize").scalar() or 0
    avg_score = db.query(func.avg(FirewallLog.threat_score)).scalar() or 0.0
    avg_latency = db.query(func.avg(FirewallLog.latency_ms)).scalar() or 0.0
    false_positives = db.query(func.count(FirewallLog.id)).filter(FirewallLog.is_false_positive == True).scalar() or 0

    # Threat Distribution
    dist_allow = db.query(func.count(FirewallLog.id)).filter(FirewallLog.threat_score <= 25).scalar() or 0
    dist_warn = db.query(func.count(FirewallLog.id)).filter((FirewallLog.threat_score > 25) & (FirewallLog.threat_score <= 50)).scalar() or 0
    dist_sanitize = db.query(func.count(FirewallLog.id)).filter((FirewallLog.threat_score > 50) & (FirewallLog.threat_score <= 75)).scalar() or 0
    dist_block = db.query(func.count(FirewallLog.id)).filter(FirewallLog.threat_score > 75).scalar() or 0

    # Top Attack Types Category Counters
    # We parse the matched_detectors field or read log values
    categories = {"direct_injection": 0, "indirect_injection": 0, "jailbreak": 0, "data_extraction": 0, "encoding": 0, "heuristics": 0}
    
    logs = db.query(FirewallLog).filter(FirewallLog.threat_score > 0).all()
    for log in logs:
        # Check matched_detectors JSON dictionary
        match_dict = log.matched_detectors
        if isinstance(match_dict, dict) and "raw_scores" in match_dict:
            raw = match_dict["raw_scores"]
            if raw.get("direct", 0) > 0: categories["direct_injection"] += 1
            if raw.get("indirect", 0) > 0: categories["indirect_injection"] += 1
            if raw.get("jailbreak", 0) > 0: categories["jailbreak"] += 1
            if raw.get("extraction", 0) > 0: categories["data_extraction"] += 1
            if raw.get("encoding", 0) > 0: categories["encoding"] += 1
            if raw.get("statistics", 0) > 20 or raw.get("entropy", 0) > 20: categories["heuristics"] += 1

    # Recent Activity Time Timeline (Last 24 Hours, grouped by hour)
    timeline_labels = []
    timeline_requests = []
    timeline_blocks = []
    
    now = datetime.now(timezone.utc)
    for i in range(23, -1, -1):
        hour_start = now - timedelta(hours=i)
        hour_label = hour_start.strftime("%H:00")
        timeline_labels.append(hour_label)
        
        # Calculate start and end for query
        start_dt = hour_start.replace(minute=0, second=0, microsecond=0)
        end_dt = start_dt + timedelta(hours=1)
        
        req_count = db.query(func.count(FirewallLog.id)).filter(
            FirewallLog.timestamp >= start_dt,
            FirewallLog.timestamp < end_dt
        ).scalar() or 0
        
        blk_count = db.query(func.count(FirewallLog.id)).filter(
            FirewallLog.timestamp >= start_dt,
            FirewallLog.timestamp < end_dt,
            FirewallLog.action_taken == "block"
        ).scalar() or 0
        
        timeline_requests.append(req_count)
        timeline_blocks.append(blk_count)

    return {
        "summary": {
            "total_requests": total,
            "blocked_requests": blocked,
            "allowed_requests": allowed,
            "warned_requests": warned,
            "sanitized_requests": sanitized,
            "average_score": round(avg_score, 2),
            "average_latency_ms": round(avg_latency, 2),
            "false_positives": false_positives
        },
        "distribution": {
            "allow": dist_allow,
            "warn": dist_warn,
            "sanitize": dist_sanitize,
            "block": dist_block
        },
        "attack_types": categories,
        "timeline": {
            "labels": timeline_labels,
            "requests": timeline_requests,
            "blocks": timeline_blocks
        }
    }

@router.get("/logs")
async def get_logs(
    action: str = "all", 
    limit: int = 50, 
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> List[Dict[str, Any]]:
    query = db.query(FirewallLog)
    if action == "block":
        query = query.filter(FirewallLog.action_taken == "block")
    elif action == "warn":
        query = query.filter(FirewallLog.action_taken == "warn")
    elif action == "sanitize":
        query = query.filter(FirewallLog.action_taken == "sanitize")
    elif action == "false_positive":
        query = query.filter(FirewallLog.is_false_positive == True)
        
    logs = query.order_by(FirewallLog.timestamp.desc()).limit(limit).all()
    
    result = []
    for l in logs:
        result.append({
            "id": l.id,
            "timestamp": l.timestamp.isoformat(),
            "client_ip": l.client_ip,
            "api_key_name": l.api_key_name,
            "request_method": l.request_method,
            "request_path": l.request_path,
            "raw_prompt": l.raw_prompt,
            "sanitized_prompt": l.sanitized_prompt,
            "threat_score": l.threat_score,
            "action_taken": l.action_taken,
            "matched_detectors": l.matched_detectors.get("matched_rules", []),
            "latency_ms": l.latency_ms,
            "is_false_positive": l.is_false_positive
        })
    return result

@router.post("/config")
async def update_config(
    mode: str = Form(...),
    threshold_allow: int = Form(...),
    threshold_warn: int = Form(...),
    threshold_sanitize: int = Form(...),
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> Response:
    config = db.query(FirewallConfigOverride).filter_by(id=1).first()
    if not config:
        config = FirewallConfigOverride(id=1)
        db.add(config)
        
    config.firewall_mode = mode
    config.threshold_allow = threshold_allow
    config.threshold_warn = threshold_warn
    config.threshold_sanitize = threshold_sanitize
    db.commit()
    
    return RedirectResponse(url="/dashboard/settings?saved=true", status_code=303)

@router.post("/logs/{log_id}/false-positive")
async def toggle_false_positive(
    log_id: int,
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> Dict[str, Any]:
    log = db.query(FirewallLog).filter_by(id=log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log entry not found")
        
    log.is_false_positive = not log.is_false_positive
    db.commit()
    
    return {
        "status": "success",
        "log_id": log_id,
        "is_false_positive": log.is_false_positive
    }

@router.post("/keys")
async def generate_key(
    name: str = Form(...),
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> Dict[str, Any]:
    raw_key = "fw_" + secrets.token_hex(20)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    new_key = ApiKey(
        key_hash=key_hash,
        name=name,
        is_active=True
    )
    db.add(new_key)
    db.commit()
    
    return {
        "status": "success",
        "key_name": name,
        "raw_api_key": raw_key
    }

@router.get("/keys")
async def list_keys(
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> List[Dict[str, Any]]:
    keys = db.query(ApiKey).all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "created_at": k.created_at.isoformat(),
            "is_active": k.is_active
        }
        for k in keys
    ]

@router.post("/keys/{key_id}/revoke")
async def revoke_key(
    key_id: int, 
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> Dict[str, Any]:
    key_record = db.query(ApiKey).filter_by(id=key_id).first()
    if not key_record:
        raise HTTPException(status_code=404, detail="API Key not found")
        
    key_record.is_active = False
    db.commit()
    return {"status": "success", "message": f"API Key {key_record.name} has been revoked."}

@router.post("/scan")
async def scan_prompt(
    prompt: str = Form(...),
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> Dict[str, Any]:
    # 1. Fetch current settings
    config = db.query(FirewallConfigOverride).filter_by(id=1).first()
    mode = config.firewall_mode if config else "learning"
    th_allow = config.threshold_allow if config else 25
    th_warn = config.threshold_warn if config else 50
    th_sanitize = config.threshold_sanitize if config else 75

    # 2. Evaluate using scoring engine
    score, meta = scoring_engine.score_prompt(prompt)

    # 3. Categorize threat level
    if score <= th_allow:
        category = "Clean / Low Threat"
    elif score <= th_warn:
        category = "Moderate Threat"
    elif score <= th_sanitize:
        category = "Elevated Threat"
    else:
        category = "Severe Threat"

    # 4. Determine policy action
    action = "allow"
    if mode == "enforce":
        if score > th_sanitize:
            action = "block"
        elif score > th_warn:
            action = "sanitize"
        elif score > th_allow:
            action = "warn"
    elif mode == "sanitize":
        if score > th_warn:
            action = "sanitize"
        elif score > th_allow:
            action = "warn"
    else:  # learning mode
        if score > th_allow:
            action = "warn"

    # 5. Sanitize prompt
    sanitized_prompt = sanitization_engine.sanitize_prompt(prompt)

    # 6. Build reasoning/decision explanation
    matched_rules = meta.get("matched_rules", [])
    if matched_rules:
        reason = f"Prompt triggered the following indicators: {', '.join(matched_rules)}."
        if action == "block":
            reason += " The threat score exceeded the security block threshold under active Enforcement policy."
        elif action == "sanitize":
            reason += " The threat score triggered sanitization rewriting to safely neutralize the payload."
    else:
        reason = "No threat signatures or anomalous statistical patterns were detected."

    return {
        "status": "success",
        "threat_score": score,
        "matched_rules": matched_rules,
        "category": category,
        "action": action,
        "sanitized_prompt": sanitized_prompt,
        "reason": reason
    }

@router.post("/change-password")
async def change_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
    user: DashboardUser = Depends(get_current_user_api)
) -> Response:
    if not verify_password(current_password, user.hashed_password):
        return RedirectResponse(url="/dashboard/settings?error=invalid_current_password", status_code=303)
    
    if len(new_password) < 6:
        return RedirectResponse(url="/dashboard/settings?error=password_too_short", status_code=303)
    
    user.hashed_password = hash_password(new_password)
    db.commit()
    
    return RedirectResponse(url="/dashboard/settings?saved=true", status_code=303)

