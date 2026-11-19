"""SQLAlchemy schema declarations; Alembic, not create_all(), changes databases."""
from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def uuid_id() -> str:
    return str(uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Product(Base):
    __tablename__ = "products"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    bundle_id: Mapped[str] = mapped_column(String(180), nullable=False, unique=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="blocked", server_default="blocked")
    rights_reference: Mapped[str | None] = mapped_column(String(300))
    features: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    __table_args__ = (CheckConstraint("status IN ('blocked','available')", name="product_status_ck"),)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_id)
    account_identifier: Mapped[str] = mapped_column(String(254), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    __table_args__ = (CheckConstraint("status IN ('active','suspended')", name="user_status_ck"),)


class License(Base):
    __tablename__ = "licenses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id", ondelete="RESTRICT"), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="subscription")
    __table_args__ = (
        UniqueConstraint("user_id", "product_id", name="uq_license_user_product"),
        Index("ix_licenses_product_status", "product_id", "status"),
        Index("ix_licenses_user_expiry", "user_id", "expires_at"),
        CheckConstraint("status IN ('active','expired','revoked')", name="license_status_ck"),
    )


class ActivationCode(Base):
    __tablename__ = "activation_codes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_id)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id", ondelete="RESTRICT"), nullable=False)
    duration_days: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="issued")
    redeemed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    redeemed_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    redeemed_license_id: Mapped[str | None] = mapped_column(ForeignKey("licenses.id", ondelete="RESTRICT"))
    __table_args__ = (
        Index("ix_activation_codes_product_status", "product_id", "status"),
        CheckConstraint("status IN ('issued','redeemed','void')", name="code_status_ck"),
        CheckConstraint("duration_days > 0", name="code_duration_ck"),
    )


class Trial(Base):
    __tablename__ = "trials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id", ondelete="RESTRICT"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (UniqueConstraint("user_id", "product_id", name="uq_trial_user_product"),)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id", ondelete="RESTRICT"), nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="unverified")
    __table_args__ = (
        Index("ix_devices_user_product", "user_id", "product_id"),
        CheckConstraint("status IN ('unverified','verified','revoked')", name="device_status_ck"),
    )


class LicenseEvent(Base):
    __tablename__ = "license_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_id)
    license_id: Mapped[str | None] = mapped_column(ForeignKey("licenses.id", ondelete="RESTRICT"))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    product_id: Mapped[str | None] = mapped_column(ForeignKey("products.id", ondelete="RESTRICT"))
    event_type: Mapped[str] = mapped_column(String(45), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(36))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    __table_args__ = (
        Index("ix_events_license_time", "license_id", "occurred_at"),
        Index("ix_events_type_time", "event_type", "occurred_at"),
    )


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_id)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (CheckConstraint("role IN ('admin','customer')", name="token_role_ck"),)


class RateBucket(Base):
    __tablename__ = "rate_buckets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_id: Mapped[str] = mapped_column(ForeignKey("api_tokens.id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    window_start: Mapped[int] = mapped_column(Integer, nullable=False)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    __table_args__ = (UniqueConstraint("token_id", "action", "window_start", name="uq_rate_bucket"),)
