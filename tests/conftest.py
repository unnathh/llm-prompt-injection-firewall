import os
import pytest

# Set test database URL environment variable before any modules are loaded
os.environ["DATABASE_URL"] = "sqlite:///./test_firewall.db"

@pytest.fixture(scope="session", autouse=True)
def setup_test_session():
    # Session-wide database initialization
    from app.database.connection import init_db
    init_db()
    yield
    # Clean up test database file after session finishes
    db_path = "test_firewall.db"
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass
