import json
from datetime import datetime, timezone
from typing import Any, Optional
from sqlalchemy import String, Text, DateTime, Float, Boolean, Integer, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class JSONEncodedType(TypeDecorator):
    """
    Custom decorator to serialize/deserialize dictionaries as JSON text in SQLite.
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Optional[Any], dialect: Any) -> Optional[str]:
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value: Optional[str], dialect: Any) -> Optional[Any]:
        if value is None:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}

class FirewallLog(Base):
    __tablename__ = "firewall_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    client_ip: Mapped[str] = mapped_column(String(50), nullable=True)
    api_key_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    request_method: Mapped[str] = mapped_column(String(10), default="POST")
    request_path: Mapped[str] = mapped_column(String(255), default="/v1/chat/completions")
    raw_prompt: Mapped[str] = mapped_column(Text)
    sanitized_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    action_taken: Mapped[str] = mapped_column(String(20))  # allow, warn, sanitize, block
    matched_detectors: Mapped[dict[str, Any]] = mapped_column(JSONEncodedType, default=dict)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

class DashboardUser(Base):
    __tablename__ = "dashboard_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    rate_limit_override: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

class FirewallConfigOverride(Base):
    """
    Allows dynamically overriding the configuration via the dashboard.
    If database contains settings, they override the .env defaults.
    """
    __tablename__ = "firewall_config_overrides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    firewall_mode: Mapped[str] = mapped_column(String(20), default="learning")
    threshold_allow: Mapped[int] = mapped_column(Integer, default=25)
    threshold_warn: Mapped[int] = mapped_column(Integer, default=50)
    threshold_sanitize: Mapped[int] = mapped_column(Integer, default=75)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
