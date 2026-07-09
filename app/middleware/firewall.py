import json
import time
from datetime import datetime, timezone
from typing import Any, Optional, Tuple
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from config.settings import settings
from app.database.connection import SessionLocal
from app.models.database import FirewallLog, FirewallConfigOverride, ApiKey
from app.scoring.engine import scoring_engine
from app.sanitization.sanitizers import sanitization_engine
from app.utils.logger import logger

class FirewallMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        # Check if we should intercept the request
        # Intercept POST requests to LLM endpoints (e.g. /v1/chat/completions)
        path = request.url.path
        if request.method != "POST" or not (path.startswith("/v1/proxy") or path.endswith("/v1/chat/completions") or path.endswith("/v1/completions")):
            return await call_next(request)

        start_time = time.perf_counter()
        client_ip = request.client.host if request.client else "unknown"
        
        # Determine API Key if provided in Authorization header
        api_key_name = await self._resolve_api_key(request)
        
        # 1. API Key Access Control
        if api_key_name == "unknown_key":
            return JSONResponse(
                status_code=401,
                content={"error": {"message": "Invalid or revoked API Key.", "type": "unauthorized"}}
            )
            
        # 2. Rate Limiting Check
        from app.utils.limiter import rate_limiter
        limiter_id = api_key_name if api_key_name else client_ip
        if not rate_limiter.is_allowed(limiter_id, max_requests=settings.RATE_LIMIT_PER_MINUTE):
            return JSONResponse(
                status_code=429,
                content={"error": {"message": "Rate limit exceeded. Please wait before retrying.", "type": "rate_limit_exceeded"}}
            )

        # Retrieve current configuration (DB override takes precedence over settings)
        db = SessionLocal()
        try:
            config = db.query(FirewallConfigOverride).filter_by(id=1).first()
            mode = config.firewall_mode if config else settings.FIREWALL_MODE
            th_allow = config.threshold_allow if config else settings.THRESHOLD_ALLOW
            th_warn = config.threshold_warn if config else settings.THRESHOLD_WARN
            th_sanitize = config.threshold_sanitize if config else settings.THRESHOLD_SANITIZE
        except Exception as e:
            logger.error("Failed to read firewall config from database, using env defaults", extra={"extra_fields": {"error": str(e)}})
            mode = settings.FIREWALL_MODE
            th_allow = settings.THRESHOLD_ALLOW
            th_warn = settings.THRESHOLD_WARN
            th_sanitize = settings.THRESHOLD_SANITIZE
        finally:
            db.close()

        # Read the request body
        try:
            body_bytes = await request.body()
            body_str = body_bytes.decode("utf-8")
            body_json = json.loads(body_str) if body_str else {}
        except Exception as e:
            logger.warning("Failed to parse request JSON body", extra={"extra_fields": {"error": str(e), "client_ip": client_ip}})
            return await call_next(request)

        # Extract prompts
        prompts = self._extract_prompts(body_json)
        if not prompts:
            # No content found to scan
            return await call_next(request)

        # Combine all prompts for holistic scanning
        combined_prompt = "\n---\n".join(prompts)

        # Score the prompt
        score, matches = scoring_engine.score_prompt(combined_prompt)

        # Decide action based on score and mode
        action = "allow"
        
        if mode == "enforce":
            if score >= th_sanitize:
                action = "block"
            elif score >= th_warn:
                action = "sanitize"
            elif score > th_allow:
                action = "warn"
        elif mode == "sanitize":
            if score >= th_warn:
                action = "sanitize"
            elif score > th_allow:
                action = "warn"
        else: # learning mode
            if score > th_allow:
                action = "warn"

        # Store firewall action and score in request state for downstream handlers / metrics
        request.state.firewall_action = action
        request.state.firewall_score = score

        sanitized_prompt = None
        modified_body_bytes = body_bytes

        # Apply sanitization if appropriate
        if action == "sanitize":
            sanitized_prompts = [sanitization_engine.sanitize_prompt(p) for p in prompts]
            sanitized_prompt = "\n---\n".join(sanitized_prompts)
            # Rebuild body with sanitized content
            modified_body_json = self._inject_sanitized_prompts(body_json, sanitized_prompts)
            modified_body_bytes = json.dumps(modified_body_json).encode("utf-8")
            
            # Reconstruct request receive channel to stream the modified body
            async def receive() -> dict:
                return {"type": "http.request", "body": modified_body_bytes, "more_body": False}
            request._receive = receive # type: ignore
        elif action == "block":
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            
            # Log blocked request to SQLite
            self._save_log(
                client_ip=client_ip,
                api_key_name=api_key_name,
                path=path,
                raw_prompt=combined_prompt,
                sanitized_prompt=None,
                score=score,
                action="block",
                matches=matches,
                latency_ms=latency_ms
            )
            
            # Log structured JSON
            logger.warning(
                "Prompt injection attempt blocked",
                extra={"extra_fields": {
                    "client_ip": client_ip,
                    "api_key_name": api_key_name,
                    "path": path,
                    "threat_score": score,
                    "action": "block",
                    "matches": matches,
                    "latency_ms": latency_ms
                }}
            )
            
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "Request blocked by security policy (potential prompt injection detected).",
                        "type": "security_violation",
                        "score": score,
                        "code": "prompt_injection_blocked"
                    }
                }
            )

        # Proceed with request (Allow / Warn / Sanitize)
        response = await call_next(request)
        
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        
        # Log transaction to SQLite
        self._save_log(
            client_ip=client_ip,
            api_key_name=api_key_name,
            path=path,
            raw_prompt=combined_prompt,
            sanitized_prompt=sanitized_prompt,
            score=score,
            action=action,
            matches=matches,
            latency_ms=latency_ms
        )

        # Log structured JSON
        log_msg = f"Request processed ({action})"
        extra = {
            "client_ip": client_ip,
            "api_key_name": api_key_name,
            "path": path,
            "threat_score": score,
            "action": action,
            "matches": matches,
            "latency_ms": latency_ms
        }
        if action == "warn":
            logger.warning(log_msg, extra={"extra_fields": extra})
        else:
            logger.info(log_msg, extra={"extra_fields": extra})

        # Add security headers to the response
        response.headers["X-Firewall-Mode"] = mode
        response.headers["X-Firewall-Score"] = str(score)
        response.headers["X-Firewall-Action"] = action
        return response

    async def _resolve_api_key(self, request: Request) -> Optional[str]:
        """
        Extract and hash API key to identify client key.
        """
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        api_key = auth_header.replace("Bearer ", "").strip()
        # In a real setup, we query the hashed key. For logs we store key name if registered.
        import hashlib
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        db = SessionLocal()
        try:
            key_record = db.query(ApiKey).filter_by(key_hash=key_hash, is_active=True).first()
            if key_record:
                return key_record.name
        except Exception:
            pass
        finally:
            db.close()
            
        return "unknown_key" if api_key else None

    def _extract_prompts(self, body: dict) -> list[str]:
        """
        Extract prompt text from standard LLM structures (messages array or prompt field).
        """
        prompts = []
        # OpenAI style chat completions
        if "messages" in body and isinstance(body["messages"], list):
            for msg in body["messages"]:
                if isinstance(msg, dict) and msg.get("role") == "user" and "content" in msg:
                    content = msg["content"]
                    if isinstance(content, str):
                        prompts.append(content)
                    elif isinstance(content, list):
                        # Handle multi-modal or list of content dicts
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                                prompts.append(part["text"])
        # OpenAI style legacy completions
        if "prompt" in body:
            prompt_field = body["prompt"]
            if isinstance(prompt_field, str):
                prompts.append(prompt_field)
            elif isinstance(prompt_field, list):
                for p in prompt_field:
                    if isinstance(p, str):
                        prompts.append(p)
                        
        return prompts

    def _inject_sanitized_prompts(self, body: dict, sanitized_prompts: list[str]) -> dict:
        """
        Inject sanitized prompts back into the JSON structure.
        """
        # Deep copy body structure
        new_body = json.loads(json.dumps(body))
        
        prompt_idx = 0
        
        if "messages" in new_body and isinstance(new_body["messages"], list):
            for msg in new_body["messages"]:
                if isinstance(msg, dict) and msg.get("role") == "user" and "content" in msg:
                    content = msg["content"]
                    if isinstance(content, str) and prompt_idx < len(sanitized_prompts):
                        msg["content"] = sanitized_prompts[prompt_idx]
                        prompt_idx += 1
                    elif isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "text" and "text" in part and prompt_idx < len(sanitized_prompts):
                                part["text"] = sanitized_prompts[prompt_idx]
                                prompt_idx += 1
                                
        if "prompt" in new_body:
            prompt_field = new_body["prompt"]
            if isinstance(prompt_field, str) and prompt_idx < len(sanitized_prompts):
                new_body["prompt"] = sanitized_prompts[prompt_idx]
                prompt_idx += 1
            elif isinstance(prompt_field, list):
                for idx, p in enumerate(prompt_field):
                    if isinstance(p, str) and prompt_idx < len(sanitized_prompts):
                        prompt_field[idx] = sanitized_prompts[prompt_idx]
                        prompt_idx += 1
                        
        return new_body

    def _save_log(self, client_ip: str, api_key_name: Optional[str], path: str, raw_prompt: str, sanitized_prompt: Optional[str], score: float, action: str, matches: dict, latency_ms: float) -> None:
        """
        Helper to safely persist transaction details.
        """
        db = SessionLocal()
        try:
            log_entry = FirewallLog(
                client_ip=client_ip,
                api_key_name=api_key_name,
                request_method="POST",
                request_path=path,
                raw_prompt=raw_prompt,
                sanitized_prompt=sanitized_prompt,
                threat_score=score,
                action_taken=action,
                matched_detectors=matches,
                latency_ms=latency_ms
            )
            db.add(log_entry)
            db.commit()
        except Exception as e:
            logger.error("Failed to write firewall log to database", extra={"extra_fields": {"error": str(e)}})
            db.rollback()
        finally:
            db.close()
