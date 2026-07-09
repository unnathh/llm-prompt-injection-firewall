from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from config.settings import settings
from app.models.database import Base, DashboardUser, FirewallConfigOverride
import bcrypt

# Handle Render postgres dialect (postgres:// -> postgresql://)
db_url = settings.DATABASE_URL or "sqlite:///./firewall.db"
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Set up connection pool (using connect_args for sqlite thread compatibility)
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_engine(
        db_url,
        connect_args=connect_args,
        echo=False
    )
else:
    engine = create_engine(
        db_url,
        echo=False
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against a bcrypt hash.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a transactional database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db() -> None:
    """
    Initialize the database, create tables, and seed initial data.
    """
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Seed default dashboard configuration if it doesn't exist
        config = db.query(FirewallConfigOverride).filter_by(id=1).first()
        if not config:
            new_config = FirewallConfigOverride(
                id=1,
                firewall_mode=settings.FIREWALL_MODE,
                threshold_allow=settings.THRESHOLD_ALLOW,
                threshold_warn=settings.THRESHOLD_WARN,
                threshold_sanitize=settings.THRESHOLD_SANITIZE
            )
            db.add(new_config)
            
        # Seed default admin user if none exists
        admin = db.query(DashboardUser).filter_by(username="admin").first()
        if not admin:
            # Default credentials: admin / admin123
            hashed_pwd = hash_password("admin123")
            default_admin = DashboardUser(
                username="admin",
                hashed_password=hashed_pwd,
                is_active=True
            )
            db.add(default_admin)
            
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
