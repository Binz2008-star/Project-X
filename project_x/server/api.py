"""FastAPI HTTP transport: strict schemas, authentication and service orchestration."""
from __future__ import annotations

from datetime import datetime
from collections.abc import Callable
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import Settings
from .db import engine_for, sessions_for
from .models import ActivationCode, ApiToken, Device, License, LicenseEvent, Product, User
from .schemas import (Activate, AdminExtend, AdminProduct, AdminUser, IssueCodes,
                      IssueToken, ProductAvailability, Renew, Revoke, TrialStart, Validate,
                      ValidationResult)
from .security import fingerprint, new_secret
from .service import DomainError, LicenseService, event, now_utc, aware


def create_app(settings: Settings | None = None, *, clock: Callable[[], datetime] = now_utc) -> FastAPI:
    cfg = settings or Settings.from_env()
    engine = engine_for(cfg.database_url)
    session_factory = sessions_for(engine)
    app = FastAPI(title="Project X Licensing API", version="0.2.0",
                  description="Authenticated, product-agnostic license service. No payment, signing or IPA operations.")
    app.state.clock = clock
    app.state.engine = engine
    bearer = HTTPBearer(auto_error=False)

    def get_db():
        with session_factory() as session:
            yield session

    def get_principal(credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                      db: Session = Depends(get_db)) -> ApiToken:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
        raw = credentials.credentials
        if not (32 <= len(raw) <= 256 and not any(c.isspace() for c in raw)):
            raise HTTPException(401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"})
        principal = db.scalar(select(ApiToken).where(
            ApiToken.token_hash == fingerprint(cfg.token_pepper, raw),
            ApiToken.revoked_at.is_(None)))
        if principal is None:
            raise HTTPException(401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"})
        if principal.role == "customer":
            user = db.get(User, principal.user_id)
            if user is None or user.status != "active":
                raise HTTPException(403, "Account unavailable")
        db.commit()  # close read transaction before service transaction starts
        return principal

    def customer(principal: ApiToken = Depends(get_principal)) -> ApiToken:
        if principal.role != "customer" or principal.user_id is None:
            raise HTTPException(403, "Customer credentials required")
        return principal

    def admin(principal: ApiToken = Depends(get_principal)) -> ApiToken:
        if principal.role != "admin":
            raise HTTPException(403, "Administrator credentials required")
        return principal

    def svc(db: Session) -> LicenseService:
        return LicenseService(db, cfg, now=clock())

    def rate_limit(db: Session, principal: ApiToken, action: str, limit: int):
        # Persist rate counters in the database: shared across API replicas.
        # This is a per-token protection, not a substitute for IP/WAF limits.
        window = int(clock().timestamp()) // 60 * 60
        used = db.execute(text("""
            INSERT INTO rate_buckets (token_id, action, window_start, hits)
            VALUES (:token, :action, :window, 1)
            ON CONFLICT (token_id, action, window_start)
            DO UPDATE SET hits = rate_buckets.hits + 1 WHERE rate_buckets.hits < :max_hits
            RETURNING hits
        """), {"token": principal.id, "action": action,
               "window": window, "max_hits": limit}).scalar_one_or_none()
        db.commit()
        if used is None:
            raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": "60"})

    def mutate(db: Session, operation):
        try:
            with db.begin():
                result = operation()
                db.flush()
                # Materialize ORM attributes while transaction is active.
                return result
        except DomainError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        except IntegrityError as exc:
            # A race or a unique/foreign-key failure must never leak internals.
            raise HTTPException(409, "Conflicting state; request not applied") from exc

    @app.exception_handler(DomainError)
    async def domain_handler(_request: Request, exc: DomainError):
        return JSONResponse(status_code=exc.status, content={"detail": str(exc)})

    @app.get("/health/live", include_in_schema=False)
    def live():
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    def ready(db: Session = Depends(get_db)):
        db.execute(text("SELECT 1"))
        return {"status": "ok"}

    def license_read(obj: License) -> dict:
        return {"license_id": obj.id, "user_id": obj.user_id, "product_id": obj.product_id,
                "activated_at": aware(obj.activated_at), "expires_at": aware(obj.expires_at),
                "status": obj.status}

    @app.post("/api/v1/licenses/activate", tags=["Licenses"])
    def activate(body: Activate, db: Session = Depends(get_db), p: ApiToken = Depends(customer)):
        rate_limit(db, p, "activation", cfg.activation_limit_per_minute)
        return mutate(db, lambda: license_read(svc(db).activate(p.user_id, body.product_id, body.activation_code)))

    @app.post("/api/v1/licenses/renew", tags=["Licenses"])
    def renew(body: Renew, db: Session = Depends(get_db), p: ApiToken = Depends(customer)):
        rate_limit(db, p, "activation", cfg.activation_limit_per_minute)
        return mutate(db, lambda: license_read(svc(db).renew(p.user_id, body.license_id, body.activation_code)))

    @app.post("/api/v1/licenses/validate", response_model=ValidationResult, tags=["Licenses"])
    def validate(body: Validate, db: Session = Depends(get_db), p: ApiToken = Depends(customer)):
        rate_limit(db, p, "validation", cfg.validation_limit_per_minute)
        return mutate(db, lambda: svc(db).validate(p.user_id, body.license_id, body.device_id))

    @app.post("/api/v1/licenses/revoke", tags=["Licenses"])
    def self_revoke(body: Revoke, db: Session = Depends(get_db), p: ApiToken = Depends(customer)):
        # Customer can revoke only their own license; admin operations are under /admin.
        def operation():
            service = svc(db)
            obj = service._license(body.license_id, p.user_id)
            return license_read(service.revoke(obj, "customer", p.user_id))
        return mutate(db, operation)

    @app.post("/api/v1/trials/start", tags=["Trials"])
    def start_trial(body: TrialStart, db: Session = Depends(get_db), p: ApiToken = Depends(customer)):
        rate_limit(db, p, "activation", cfg.activation_limit_per_minute)
        return mutate(db, lambda: license_read(svc(db).start_trial(p.user_id, body.product_id)))

    @app.get("/api/v1/licenses/{license_id}", tags=["Licenses"])
    def get_license(license_id: str, db: Session = Depends(get_db), p: ApiToken = Depends(customer)):
        def operation():
            service = svc(db)
            obj = service._license(license_id, p.user_id)
            service.validate(p.user_id, license_id, None)  # persist lazy expiration
            return license_read(obj)
        return mutate(db, operation)

    @app.get("/api/v1/products", tags=["Products"])
    def list_products(db: Session = Depends(get_db), _p: ApiToken = Depends(get_principal)):
        items = db.scalars(select(Product).where(Product.status == "available",
                          Product.rights_reference.is_not(None)).order_by(Product.id)).all()
        return [{"product_id": x.id, "name": x.name, "bundle_id": x.bundle_id,
                 "version": x.version, "features": x.features} for x in items]

    @app.post("/api/v1/devices/register", tags=["Devices"])
    def register_device(body: TrialStart, db: Session = Depends(get_db), p: ApiToken = Depends(customer)):
        rate_limit(db, p, "activation", cfg.activation_limit_per_minute)
        def operation():
            x = svc(db).register_device(p.user_id, body.product_id)
            return {"device_id": x.id, "status": x.status,
                    "registered_at": aware(x.registered_at)}
        return mutate(db, operation)

    # All administrative writes below require an administrator bearer token.
    @app.post("/api/v1/admin/products", tags=["Administration"], status_code=201)
    def create_product(body: AdminProduct, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            if body.status == "available" and not body.rights_reference:
                raise DomainError("Available products require a rights reference", 422)
            item = Product(id=body.product_id, name=body.name, bundle_id=body.bundle_id,
                           version=body.version, status=body.status,
                           rights_reference=body.rights_reference, features=body.features)
            db.add(item)
            db.flush()
            event(db, "product_created", "admin", p.id, product_id=item.id,
                  now=clock(), details={"status": item.status})
            return {"product_id": item.id, "status": item.status}
        return mutate(db, operation)

    @app.patch("/api/v1/admin/products/{product_id}", tags=["Administration"])
    def set_product(product_id: str, body: ProductAvailability, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            item = db.get(Product, product_id)
            if item is None:
                raise DomainError("Product not found", 404)
            if body.status == "available" and not body.rights_reference:
                raise DomainError("Available products require a rights reference", 422)
            item.status = body.status
            item.rights_reference = body.rights_reference
            event(db, "product_availability_changed", "admin", p.id,
                  product_id=item.id, now=clock(), details={"status": item.status})
            return {"product_id": item.id, "status": item.status}
        return mutate(db, operation)

    @app.get("/api/v1/admin/products", tags=["Administration"])
    def admin_products(db: Session = Depends(get_db), _p: ApiToken = Depends(admin)):
        return [{"product_id": p.id, "status": p.status,
                 "rights_reference": p.rights_reference} for p in db.scalars(select(Product).order_by(Product.id)).all()]

    @app.post("/api/v1/admin/users", tags=["Administration"], status_code=201)
    def create_user(body: AdminUser, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            obj = User(account_identifier=body.account_identifier, created_at=clock(), status="active")
            db.add(obj)
            db.flush()
            event(db, "customer_created", "admin", p.id, user_id=obj.id, now=clock())
            return {"user_id": obj.id, "status": obj.status}
        return mutate(db, operation)

    @app.get("/api/v1/admin/users", tags=["Administration"])
    def list_users(offset: int = 0, limit: int = 100, db: Session = Depends(get_db), _p: ApiToken = Depends(admin)):
        if not (0 <= offset <= 100000 and 1 <= limit <= 100):
            raise HTTPException(422, "Invalid pagination")
        return [{"user_id": u.id, "account_identifier": u.account_identifier,
                 "created_at": aware(u.created_at), "status": u.status}
                for u in db.scalars(select(User).order_by(User.created_at).offset(offset).limit(limit)).all()]

    @app.post("/api/v1/admin/tokens", tags=["Administration"], status_code=201)
    def customer_token(body: IssueToken, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            user = db.get(User, body.user_id)
            if user is None or user.status != "active":
                raise DomainError("User unavailable", 404)
            raw = new_secret()
            db.add(ApiToken(token_hash=fingerprint(cfg.token_pepper, raw), role="customer",
                            user_id=body.user_id, created_at=clock()))
            event(db, "customer_token_created", "admin", p.id,
                  user_id=body.user_id, now=clock())
            return {"token": raw, "note": "Shown once; store securely."}
        return mutate(db, operation)

    @app.post("/api/v1/admin/codes/batch", tags=["Administration"], status_code=201)
    def issue_codes(body: IssueCodes, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        return mutate(db, lambda: {"codes": svc(db).issue_codes(
            body.product_id, body.duration_days, body.count, p.id)})

    @app.get("/api/v1/admin/codes", tags=["Administration"])
    def list_codes(offset: int = 0, limit: int = 100,
                   db: Session = Depends(get_db), _p: ApiToken = Depends(admin)):
        if not (0 <= offset <= 100000 and 1 <= limit <= 100):
            raise HTTPException(422, "Invalid pagination")
        # Never return the raw code or its hash through listing APIs.
        return [{"code_id": c.id, "product_id": c.product_id,
                 "duration_days": c.duration_days, "status": c.status,
                 "redeemed_at": aware(c.redeemed_at) if c.redeemed_at else None,
                 "redeemed_license_id": c.redeemed_license_id}
                for c in db.scalars(select(ActivationCode)
                    .order_by(ActivationCode.id).offset(offset).limit(limit)).all()]

    @app.get("/api/v1/admin/licenses", tags=["Administration"])
    def list_licenses(offset: int = 0, limit: int = 100,
                      db: Session = Depends(get_db), _p: ApiToken = Depends(admin)):
        if not (0 <= offset <= 100000 and 1 <= limit <= 100):
            raise HTTPException(422, "Invalid pagination")
        return [license_read(x) for x in db.scalars(
            select(License).order_by(License.activated_at.desc()).offset(offset).limit(limit)).all()]

    @app.post("/api/v1/admin/licenses/{license_id}/revoke", tags=["Administration"])
    def admin_revoke(license_id: str, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            obj = db.get(License, license_id)
            if obj is None:
                raise DomainError("License not found", 404)
            return license_read(svc(db).revoke(obj, "admin", p.id))
        return mutate(db, operation)

    @app.post("/api/v1/admin/licenses/{license_id}/extend", tags=["Administration"])
    def admin_extend(license_id: str, body: AdminExtend,
                     db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            if body.days not in cfg.allowed_durations:
                raise DomainError("Duration not configured", 422)
            obj = db.get(License, license_id)
            if obj is None:
                raise DomainError("License not found", 404)
            return license_read(svc(db).admin_extend(obj, body.days, p.id))
        return mutate(db, operation)

    @app.post("/api/v1/admin/tokens/{token_id}/revoke", tags=["Administration"])
    def admin_revoke_token(token_id: str, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            target = db.get(ApiToken, token_id)
            if target is None:
                raise DomainError("Token not found", 404)
            if target.id == p.id:
                raise DomainError("Use the offline CLI to revoke your own admin token", 409)
            target.revoked_at = clock()
            event(db, "api_token_revoked", "admin", p.id,
                  user_id=target.user_id, now=clock(), details={"token_id": token_id})
            return {"token_id": target.id, "revoked": True}
        return mutate(db, operation)

    @app.post("/api/v1/admin/users/{user_id}/suspend", tags=["Administration"])
    def admin_suspend_user(user_id: str, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            target = db.get(User, user_id)
            if target is None:
                raise DomainError("User not found", 404)
            target.status = "suspended"
            event(db, "customer_suspended", "admin", p.id,
                  user_id=target.id, now=clock())
            return {"user_id": target.id, "status": target.status}
        return mutate(db, operation)

    @app.get("/api/v1/admin/events", tags=["Administration"])
    def list_events(offset: int = 0, limit: int = 100, license_id: str | None = None,
                    db: Session = Depends(get_db), _p: ApiToken = Depends(admin)):
        if not (0 <= offset <= 100000 and 1 <= limit <= 100):
            raise HTTPException(422, "Invalid pagination")
        stmt = select(LicenseEvent).order_by(LicenseEvent.occurred_at.desc(), LicenseEvent.id).offset(offset).limit(limit)
        if license_id:
            stmt = stmt.where(LicenseEvent.license_id == license_id)
        return [{"event_id": e.id, "event_type": e.event_type,
                 "license_id": e.license_id, "user_id": e.user_id,
                 "product_id": e.product_id, "actor_role": e.actor_role,
                 "occurred_at": aware(e.occurred_at), "details": e.details}
                for e in db.scalars(stmt).all()]

    @app.post("/api/v1/admin/devices/{device_id}/revoke", tags=["Administration"])
    def admin_revoke_device(device_id: str, db: Session = Depends(get_db), p: ApiToken = Depends(admin)):
        def operation():
            device = db.get(Device, device_id)
            if device is None:
                raise DomainError("Device not found", 404)
            device.status = "revoked"
            event(db, "device_revoked", "admin", p.id, user_id=device.user_id,
                  product_id=device.product_id, now=clock(), details={"device_id": device.id})
            return {"device_id": device.id, "status": device.status}
        return mutate(db, operation)

    return app

