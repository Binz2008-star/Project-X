"""Product-agnostic licensing business rules, transactionally applied by callers.

This layer knows SQLAlchemy entities, but not FastAPI, HTTP request schemas or API
routes. The application supplies authenticated user identity, never the caller.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .config import Settings
from .models import ActivationCode, Device, License, LicenseEvent, Product, Trial, User
from .security import fingerprint, new_secret


class DomainError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def aware(value: datetime) -> datetime:
    """SQLite stores timezone-naive UTC; PostgreSQL stores timestamptz."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def event(db: Session, event_type: str, actor_role: str, actor_id: str | None,
          *, license: License | None = None, user_id: str | None = None,
          product_id: str | None = None, now: datetime | None = None,
          details: dict | None = None) -> None:
    db.add(LicenseEvent(
        license_id=license.id if license else None,
        user_id=license.user_id if license else user_id,
        product_id=license.product_id if license else product_id,
        event_type=event_type, actor_role=actor_role, actor_id=actor_id,
        occurred_at=now or now_utc(), details=details or {},
    ))


class LicenseService:
    def __init__(self, db: Session, settings: Settings, now: datetime | None = None):
        self.db = db
        self.settings = settings
        self.now = aware(now) if now else now_utc()

    def _customer(self, user_id: str) -> User:
        user = self.db.get(User, user_id)
        if user is None or user.status != "active":
            raise DomainError("Account not active", 403)
        return user

    def _product(self, product_id: str) -> Product:
        product = self.db.get(Product, product_id)
        if product is None or product.status != "available" or not product.rights_reference:
            raise DomainError("Product unavailable", 404)
        return product

    def _license(self, license_id: str, user_id: str) -> License:
        obj = self.db.get(License, license_id)
        if obj is None or obj.user_id != user_id:
            raise DomainError("License not found", 404)
        return obj

    def _claim_code(self, code: str, product_id: str, user_id: str,
                    operation: str, license_id: str | None = None) -> tuple[ActivationCode, bool]:
        """Claim atomically or return the same account's completed same-operation retry.

        A retry never grants time twice and never appends a second redemption
        event. Codes cannot be replayed across users or operations. The existing
        unique code hash and conditional update protect concurrent claimants.
        """
        code_hash = fingerprint(self.settings.code_pepper, code)
        claimed_id = self.db.execute(
            update(ActivationCode)
            .where(ActivationCode.code_hash == code_hash,
                   ActivationCode.product_id == product_id,
                   ActivationCode.status == "issued")
            .values(status="redeemed", redeemed_at=self.now, redeemed_by=user_id,
                    redemption_operation=operation)
            .returning(ActivationCode.id)
        ).scalar_one_or_none()
        if claimed_id:
            return self.db.get(ActivationCode, claimed_id), False
        previous = self.db.scalar(select(ActivationCode).where(ActivationCode.code_hash == code_hash))
        if (previous is None or previous.status != "redeemed" or
                previous.product_id != product_id or previous.redeemed_by != user_id or
                previous.redemption_operation != operation or
                not previous.redeemed_license_id or
                (license_id is not None and previous.redeemed_license_id != license_id)):
            raise DomainError("Invalid or already redeemed activation code")
        original_license = self.db.get(License, previous.redeemed_license_id)
        if (original_license is None or original_license.user_id != user_id or
                original_license.product_id != product_id or original_license.status == "revoked"):
            raise DomainError("Invalid or already redeemed activation code")
        return previous, True

    def _redemption_event(self, license: License, claimed: ActivationCode,
                          user_id: str, operation: str) -> None:
        event(self.db, "code_redeemed", "customer", user_id, license=license,
              now=self.now, details={"code_id": claimed.id,
                                     "duration_days": claimed.duration_days,
                                     "operation": operation})

    def _extend(self, obj: License, days: int) -> None:
        baseline = max(self.now, aware(obj.expires_at)) if obj.status == "active" else self.now
        obj.expires_at = baseline + timedelta(days=days)
        obj.status = "active"
        obj.source = "subscription"

    def activate(self, user_id: str, product_id: str, code: str) -> License:
        self._customer(user_id)
        self._product(product_id)
        existing = self.db.scalar(select(License).where(
            License.user_id == user_id, License.product_id == product_id).with_for_update())
        if existing is not None and existing.status == "revoked":
            raise DomainError("Revoked licenses cannot be reused")
        claimed, repeated = self._claim_code(code, product_id, user_id, "activation")
        if repeated:
            # Another concurrent transaction may have committed after our
            # initial license lookup. Fetch by the persisted redemption link.
            return self.db.get(License, claimed.redeemed_license_id)
        if existing is not None and existing.source != "trial":
            raise DomainError("Existing license must be renewed")
        if existing is None:
            obj = License(user_id=user_id, product_id=product_id,
                          activated_at=self.now, expires_at=self.now + timedelta(days=claimed.duration_days),
                          status="active", source="subscription")
            self.db.add(obj)
            self.db.flush()
        else:
            obj = existing
            self._extend(obj, claimed.duration_days)
            self.db.flush()
        claimed.redeemed_license_id = obj.id
        self._redemption_event(obj, claimed, user_id, "activation")
        event(self.db, "activation", "customer", user_id, license=obj, now=self.now,
              details={"duration_days": claimed.duration_days, "code_id": claimed.id})
        return obj

    def renew(self, user_id: str, license_id: str, code: str) -> License:
        self._customer(user_id)
        obj = self._license(license_id, user_id)
        if obj.status == "revoked":
            raise DomainError("Revoked license cannot be renewed")
        self._product(obj.product_id)
        # Lock the license row before calculating the extended expiry: two
        # independent renewal codes must not overwrite each other's extensions.
        obj = self.db.scalar(select(License).where(License.id == license_id)
                             .with_for_update().execution_options(populate_existing=True))
        if obj.status == "revoked":
            raise DomainError("Revoked license cannot be renewed")
        claimed, repeated = self._claim_code(code, obj.product_id, user_id,
                                             "renewal", license_id=license_id)
        if repeated:
            return obj
        self._extend(obj, claimed.duration_days)
        claimed.redeemed_license_id = obj.id
        self._redemption_event(obj, claimed, user_id, "renewal")
        event(self.db, "renewal", "customer", user_id, license=obj, now=self.now,
              details={"duration_days": claimed.duration_days, "code_id": claimed.id})
        return obj

    def start_trial(self, user_id: str, product_id: str) -> License:
        self._customer(user_id)
        self._product(product_id)
        if self.db.scalar(select(License.id).where(
                License.user_id == user_id, License.product_id == product_id)):
            raise DomainError("License already exists; trial is not available")
        # Unique(user_id, product_id) is enforced in the database. The outer
        # transaction rolls back the trial and license on any conflict.
        self.db.add(Trial(user_id=user_id, product_id=product_id,
                          started_at=self.now,
                          expires_at=self.now + timedelta(days=self.settings.trial_days)))
        obj = License(user_id=user_id, product_id=product_id,
                      activated_at=self.now, expires_at=self.now + timedelta(days=self.settings.trial_days),
                      status="active", source="trial")
        self.db.add(obj)
        self.db.flush()
        event(self.db, "trial_started", "customer", user_id, license=obj, now=self.now)
        return obj

    def validate(self, user_id: str, license_id: str, device_id: str | None) -> dict:
        self._customer(user_id)
        obj = self._license(license_id, user_id)
        product = self.db.get(Product, obj.product_id)
        device_status = "not_registered"
        if device_id:
            device = self.db.get(Device, device_id)
            if device is not None and device.user_id == user_id and device.product_id == obj.product_id:
                device_status = device.status
        if obj.status == "active" and aware(obj.expires_at) <= self.now:
            obj.status = "expired"
            event(self.db, "expiration", "system", None, license=obj, now=self.now)
        status = obj.status
        if product is None or product.status != "available" or not product.rights_reference:
            status = "product_unavailable"
        return {
            "license_status": status,
            "product_id": obj.product_id,
            "expiration_timestamp": aware(obj.expires_at),
            "available_features": list(product.features or []) if product and status == "active" else [],
            "device_registration_status": device_status,
        }

    def revoke(self, obj: License, actor_role: str, actor_id: str) -> License:
        obj = self.db.scalar(select(License).where(License.id == obj.id)
                             .with_for_update().execution_options(populate_existing=True))
        if obj.status == "revoked":
            return obj
        obj.status = "revoked"
        event(self.db, "revocation", actor_role, actor_id, license=obj, now=self.now)
        return obj

    def register_device(self, user_id: str, product_id: str) -> Device:
        self._customer(user_id)
        self._product(product_id)
        # PostgreSQL locks the account row, serializing device registrations
        # even when no device rows exist yet. SQLite callers acquire a write
        # reservation (BEGIN IMMEDIATE) before reading the count.
        self.db.execute(select(User.id).where(User.id == user_id).with_for_update()).scalar_one()
        count = self.db.scalar(select(func.count(Device.id)).where(
            Device.user_id == user_id, Device.product_id == product_id,
            Device.status != "revoked"))
        if count >= self.settings.max_devices_per_product:
            raise DomainError("Device registration limit reached")
        device = Device(user_id=user_id, product_id=product_id,
                        registered_at=self.now, status="unverified")
        self.db.add(device)
        self.db.flush()
        event(self.db, "device_registered", "customer", user_id,
              user_id=user_id, product_id=product_id, now=self.now,
              details={"device_id": device.id, "verification": "not_attested"})
        return device

    def issue_codes(self, product_id: str, duration_days: int, count: int, actor_id: str) -> list[str]:
        self._product(product_id)
        if duration_days not in self.settings.allowed_durations:
            raise DomainError("Duration not configured", 422)
        issued = []
        for _ in range(count):
            secret = new_secret()
            self.db.add(ActivationCode(code_hash=fingerprint(self.settings.code_pepper, secret),
                                       product_id=product_id, duration_days=duration_days,
                                       status="issued"))
            issued.append(secret)
        event(self.db, "codes_issued", "admin", actor_id, product_id=product_id,
              now=self.now, details={"count": count, "duration_days": duration_days})
        return issued

    def admin_extend(self, obj: License, days: int, actor_id: str):
        obj = self.db.scalar(select(License).where(License.id == obj.id)
                             .with_for_update().execution_options(populate_existing=True))
        if obj.status == "revoked":
            raise DomainError("Revoked license cannot be extended")
        self._extend(obj, days)
        event(self.db, "admin_extension", "admin", actor_id, license=obj,
              now=self.now, details={"duration_days": days})
        return obj
