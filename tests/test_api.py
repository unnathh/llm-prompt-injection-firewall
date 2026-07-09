import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import init_db, SessionLocal
from app.models.database import FirewallLog

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    # Force test sqlite db
    os.environ["DATABASE_URL"] = "sqlite:///./test_firewall.db"
    init_db()
    yield
    # Cleanup database files after test module finishes
    db_paths = ["test_firewall.db"]
    for path in db_paths:
        if os.path.exists(path):
            try:
                os.remove(path)
            except PermissionError:
                pass

@pytest.fixture
def client():
    return TestClient(app)

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "LLM Prompt Injection Firewall"}

def test_metrics_endpoint(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "firewall_requests_total" in response.text

def test_proxy_chat_completions_mock(client):
    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Hello, how are you today?"}
        ]
    }
    response = client.post("/v1/chat/completions", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert "choices" in data
    assert len(data["choices"]) > 0
    assert "mocked" in data["model"]
    
    # Check database log was created
    db = SessionLocal()
    try:
        log = db.query(FirewallLog).order_by(FirewallLog.id.desc()).first()
        assert log is not None
        assert log.raw_prompt == "Hello, how are you today?"
        assert log.threat_score == 0.0
        assert log.action_taken == "allow"
    finally:
        db.close()

def test_api_key_access_control(client):
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello"}]
    }
    # Invalid key
    response = client.post(
        "/v1/chat/completions",
        json=payload,
        headers={"Authorization": "Bearer fw_invalidkey123"}
    )
    assert response.status_code == 401
    assert "Invalid or revoked API Key" in response.json()["error"]["message"]

def test_rate_limiting(client):
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Test rate limiter"}]
    }
    from app.utils.limiter import rate_limiter
    original_check = rate_limiter.is_allowed
    try:
        rate_limiter.is_allowed = lambda *args, **kwargs: False
        response = client.post("/v1/chat/completions", json=payload)
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["error"]["message"]
    finally:
        rate_limiter.is_allowed = original_check

def test_unauthenticated_api_endpoints(client):
    # Try fetching stats without JWT
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 401
    assert "Session cookie missing" in response.json()["detail"]

def test_unauthenticated_ui_endpoints(client):
    # Try UI dashboard page without JWT (should redirect)
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/dashboard/login"

def test_login_and_jwt_token(client):
    # Valid login
    login_data = {
        "username": "admin",
        "password": "admin123"
    }
    response = client.post("/api/dashboard/login", data=login_data, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert "dashboard_session" in response.cookies
    
    # Verify we can now access stats with the set cookie
    stats_resp = client.get("/api/dashboard/stats")
    assert stats_resp.status_code == 200
    assert "summary" in stats_resp.json()

def test_change_password(client):
    # 1. Login to get session
    login_data = {
        "username": "admin",
        "password": "admin123"
    }
    client.post("/api/dashboard/login", data=login_data)
    
    # 2. Change password
    change_data = {
        "current_password": "admin123",
        "new_password": "newpassword123"
    }
    response = client.post("/api/dashboard/change-password", data=change_data, follow_redirects=False)
    assert response.status_code == 303
    assert "saved=true" in response.headers["location"]
    
    # 3. Log out (delete cookie)
    client.get("/dashboard/logout")
    
    # 4. Try logging in with old password (should fail)
    response = client.post("/api/dashboard/login", data=login_data, follow_redirects=False)
    assert response.status_code == 303
    assert "invalid_credentials" in response.headers["location"]
    
    # 5. Log in with new password (should succeed)
    new_login_data = {
        "username": "admin",
        "password": "newpassword123"
    }
    response = client.post("/api/dashboard/login", data=new_login_data, follow_redirects=False)
    assert response.status_code == 303
    
    # 6. Change password back to admin123 to preserve clean state
    reset_data = {
        "current_password": "newpassword123",
        "new_password": "admin123"
    }
    client.post("/api/dashboard/change-password", data=reset_data)
