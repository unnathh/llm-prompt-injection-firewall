import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List
import httpx
from fastapi import FastAPI, Depends, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest, multiprocess
from prometheus_client import Counter, Histogram

from config.settings import settings
from app.database.connection import init_db
from app.middleware.firewall import FirewallMiddleware
from app.utils.logger import logger
from app.dashboard.routes import router as dashboard_router
from app.api.dashboard_api import router as dashboard_api_router
from app.models.schemas import ChatCompletionRequest

# Initialize Prometheus Metrics
registry = CollectorRegistry()
REQUESTS_TOTAL = Counter(
    "firewall_requests_total",
    "Total requests processed by the firewall",
    ["method", "path", "action"],
    registry=registry
)
REQUESTS_LATENCY = Histogram(
    "firewall_request_latency_seconds",
    "Request latency in seconds",
    ["method", "path"],
    registry=registry
)

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Startup actions
    logger.info("Initializing SQLite Database...")
    init_db()
    logger.info("Database initialized successfully.")
    
    # Initialize HTTP client for proxying
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    
    yield
    
    # Shutdown actions
    logger.info("Closing HTTP proxy client...")
    await app.state.http_client.aclose()
    logger.info("Application shutdown complete.")

app = FastAPI(
    title=settings.APP_NAME,
    description="A secure gateway detecting, scoring, and blocking prompt injection attacks.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Firewall Middleware (registered before other routes to intercept proxy calls)
app.add_middleware(FirewallMiddleware)

# Mount static files and register dashboard routers
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(dashboard_router)
app.include_router(dashboard_api_router)

# Mock fallback for LLM completions
def get_mock_completion(messages: List[Dict[str, str]], model: str) -> Dict[str, Any]:
    # Extract last user message for contextual simulation
    user_msg = "your request"
    for msg in reversed(messages):
        if msg.get("role") == "user":
            user_msg = f"'{msg.get('content')}'"
            break
            
    return {
        "id": "chatcmpl-mock" + str(int(time.time())),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": f"{model}-mocked",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"Hello! This is a mock response from the LLM Prompt Injection Firewall. Your prompt {user_msg} was evaluated and permitted by the firewall rules."
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": len(user_msg) // 4,
            "completion_tokens": 30,
            "total_tokens": (len(user_msg) // 4) + 30
        }
    }

# Proxy Router
@app.post("/v1/chat/completions")
async def chat_completions(request: Request, payload: ChatCompletionRequest) -> Response:
    """
    OpenAI-compatible proxy endpoint.
    If DOWNSTREAM_LLM_URL is configured, it forwards the sanitized payload.
    Otherwise, it returns a simulated mock response.
    """
    start_time = time.perf_counter()
    path = request.url.path
    method = request.method
    
    body = payload.model_dump(exclude_none=True)
    model = payload.model
    messages = [m.model_dump() for m in payload.messages]

    # Get firewall action stored in request state by middleware
    fw_action = getattr(request.state, "firewall_action", "allow")
    
    # 1. Check if downstream LLM is configured
    if settings.DOWNSTREAM_LLM_URL:
        logger.info(f"Forwarding request to downstream LLM: {settings.DOWNSTREAM_LLM_URL}")
        client = request.app.state.http_client
        
        # Build headers, passing along credentials
        headers = {}
        if settings.DOWNSTREAM_LLM_API_KEY:
            headers["Authorization"] = f"Bearer {settings.DOWNSTREAM_LLM_API_KEY}"
        else:
            auth = request.headers.get("Authorization")
            if auth:
                headers["Authorization"] = auth
        
        # Clean Content-Length header to let HTTPX compute it correctly
        headers["Content-Type"] = "application/json"
        
        try:
            url = f"{settings.DOWNSTREAM_LLM_URL.rstrip('/')}/chat/completions"
            response = await client.post(
                url,
                json=body,
                headers=headers,
                timeout=30.0
            )
            
            # Record metrics
            REQUESTS_TOTAL.labels(method=method, path=path, action=fw_action).inc()
            REQUESTS_LATENCY.labels(method=method, path=path).observe(time.perf_counter() - start_time)
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        except httpx.RequestError as exc:
            logger.error(f"Downstream proxy request failed: {exc}")
            raise HTTPException(status_code=502, detail="Error communicating with downstream LLM server")
    else:
        # Simulate completion response
        mock_response = get_mock_completion(messages, model)
        
        REQUESTS_TOTAL.labels(method=method, path=path, action=fw_action).inc()
        REQUESTS_LATENCY.labels(method=method, path=path).observe(time.perf_counter() - start_time)
        
        return JSONResponse(content=mock_response)

# Health endpoint
@app.get("/health")
def health_check() -> Dict[str, str]:
    return {"status": "healthy", "service": "LLM Prompt Injection Firewall"}

# Metrics endpoint
@app.get("/metrics")
def metrics() -> Response:
    """
    Exposes metrics for Prometheus scraping.
    """
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
