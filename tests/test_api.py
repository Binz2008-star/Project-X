"""Integration tests run against a migrated SQLite database and genuine HTTP routes."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import secrets
from pathlib import Path
from sqlalchemy.engine.url import make_url
from project_x.server.db import engine_for

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from project_x.server.api import create_app
from project_x.server.config import Settings
from project_x.server.models import ActivationCode, ApiToken, License, LicenseEvent, Product
from project_x.server.security import fingerprint

NOW = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)
P_ID = "demo.owned"


@pytest.fixture(params=["sqlite", "postgresql"])
def ctx(tmp_path, monkeypatch, request):
    schema = None
    pg_base = None
    if request.param == "postgresql":
        pg_base = os.getenv("PROJECT_X_TEST_POSTGRESQL_URL")
        if not pg_base:
            pytest.skip("PostgreSQL integration database not provided")
        schema = "test_" + secrets.token_hex(8)
        admin_engine = engine_for(pg_base)
        with admin_engine.begin() as conn:
            conn.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        admin_engine.dispose()
        url = str(make_url(pg_base).update_query_dict({"options": f"-csearch_path={schema}"}))
    else:
        url = f"sqlite:///{tmp_path / 'api.db'}"
    settings = Settings(database_url=url, code_pepper="A" * 40, token_pepper="B" * 40)
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("CODE_PEPPER", settings.code_pepper)
    monkeypatch.setenv("TOKEN_PEPPER", settings.token_pepper)
    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "migrations"))
    command.upgrade(cfg, "head")
    clock_state = [NOW]
    app = create_app(settings, clock=lambda: clock_state[0])
    admin_raw = "admin_" + "T" * 45
    with Session(app.state.engine) as db:
        db.add(ApiToken(token_hash=fingerprint(settings.token_pepper, admin_raw), role="admin", created_at=NOW))
        db.commit()
    with TestClient(app) as client:
        yield {"client": client, "app": app, "settings": settings,
               "clock": clock_state, "admin_token": admin_raw, "admin": {"Authorization": f"Bearer {admin_raw}"}}
    app.state.engine.dispose()
    if pg_base and schema:
        admin_engine = engine_for(pg_base)
        with admin_engine.begin() as conn:
            conn.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin_engine.dispose()


def setup(ctx, product=True):
    client = ctx["client"]
    admin = ctx["admin"]
    if product:
        r = client.post("/api/v1/admin/products", headers=admin, json={
            "product_id": P_ID, "name": "Authorized demo app", "bundle_id": "test.projectx.demo",
            "version": "1", "features": ["theme", "export"], "status": "available",
            "rights_reference": "owned-internal-test-app"
        })
        assert r.status_code == 201, r.text
    r = client.post("/api/v1/admin/users", headers=admin, json={"account_identifier": "test@example.invalid"})
    assert r.status_code == 201, r.text
    user_id = r.json()["user_id"]
    token = client.post("/api/v1/admin/tokens", headers=admin, json={"user_id": user_id}).json()["token"]
    return user_id, {"Authorization": f"Bearer {token}"}


def issue(ctx, duration=30, count=1):
    r = ctx["client"].post("/api/v1/admin/codes/batch", headers=ctx["admin"], json={
        "product_id": P_ID, "duration_days": duration, "count": count})
    assert r.status_code == 201, r.text
    return r.json()["codes"]


def activation(ctx, auth, code):
    return ctx["client"].post("/api/v1/licenses/activate", headers=auth,
                              json={"product_id": P_ID, "activation_code": code})


def validation(ctx, auth, license_id, device_id=None):
    return ctx["client"].post("/api/v1/licenses/validate", headers=auth,
                              json={"license_id": license_id, "device_id": device_id})


def test_initial_activation_and_features(ctx):
    user_id, auth = setup(ctx)
    code = issue(ctx)[0]
    resp = activation(ctx, auth, code)
    assert resp.status_code == 200, resp.text
    obj = resp.json()
    assert obj["user_id"] == user_id
    assert obj["expires_at"] == "2026-12-20T10:00:00+00:00"
    val = validation(ctx, auth, obj["license_id"])
    assert val.status_code == 200, val.text
    assert val.json() == {"license_status": "active", "product_id": P_ID,
                          "expiration_timestamp": "2026-12-20T10:00:00Z",
                          "available_features": ["theme", "export"],
                          "device_registration_status": "not_registered"}
    with Session(ctx["app"].state.engine) as db:
        assert db.scalar(select(ActivationCode).where(ActivationCode.product_id == P_ID)).code_hash != code
        assert db.scalar(select(LicenseEvent).where(LicenseEvent.event_type == "activation")) is not None


def test_duplicate_redemption(ctx):
    _, auth = setup(ctx)
    code = issue(ctx)[0]
    assert activation(ctx, auth, code).status_code == 200
    assert activation(ctx, auth, code).status_code == 409


def test_expiry_and_renewal(ctx):
    _, auth = setup(ctx)
    first = activation(ctx, auth, issue(ctx)[0]).json()
    ctx["clock"][0] = NOW + timedelta(days=31)
    r = validation(ctx, auth, first["license_id"])
    assert r.json()["license_status"] == "expired"
    assert r.json()["available_features"] == []
    renewed = ctx["client"].post("/api/v1/licenses/renew", headers=auth,
             json={"license_id": first["license_id"], "activation_code": issue(ctx, 90)[0]})
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["expires_at"] == "2027-03-21T10:00:00+00:00"
    assert validation(ctx, auth, first["license_id"]).json()["license_status"] == "active"


def test_renewal_active_extends_current_expiration(ctx):
    _, auth = setup(ctx)
    first = activation(ctx, auth, issue(ctx)[0]).json()
    renewed = ctx["client"].post("/api/v1/licenses/renew", headers=auth,
            json={"license_id": first["license_id"], "activation_code": issue(ctx)[0]})
    assert renewed.status_code == 200
    assert renewed.json()["expires_at"] == "2027-01-19T10:00:00+00:00"


def test_revoked_cannot_reactivate(ctx):
    _, auth = setup(ctx)
    lic = activation(ctx, auth, issue(ctx)[0]).json()
    assert ctx["client"].post("/api/v1/licenses/revoke", headers=auth,
             json={"license_id": lic["license_id"]}).status_code == 200
    assert validation(ctx, auth, lic["license_id"]).json()["license_status"] == "revoked"
    assert ctx["client"].post("/api/v1/licenses/renew", headers=auth, json={
             "license_id": lic["license_id"], "activation_code": issue(ctx)[0]}).status_code == 409


def test_trial_expiration_reuse_and_upgrade(ctx):
    _, auth = setup(ctx)
    trial = ctx["client"].post("/api/v1/trials/start", headers=auth,
                               json={"product_id": P_ID})
    assert trial.status_code == 200, trial.text
    lic = trial.json()["license_id"]
    assert trial.json()["expires_at"] == "2026-11-27T10:00:00+00:00"
    assert ctx["client"].post("/api/v1/trials/start", headers=auth,
                               json={"product_id": P_ID}).status_code == 409
    ctx["clock"][0] = NOW + timedelta(days=7)
    assert validation(ctx, auth, lic).json()["license_status"] == "expired"
    active = activation(ctx, auth, issue(ctx)[0])
    assert active.status_code == 200, active.text
    assert active.json()["license_id"] == lic


def test_invalid_product_blocks_and_rights_gate(ctx):
    _, auth = setup(ctx, product=False)
    unknown = ctx["client"].post("/api/v1/trials/start", headers=auth,
                                 json={"product_id": "nonexistent"})
    assert unknown.status_code == 404
    assert ctx["client"].post("/api/v1/admin/products", headers=ctx["admin"], json={
        "product_id": P_ID, "name": "demo", "bundle_id": "test.demo",
        "version": "1", "status": "available"}).status_code == 422


def test_auth_required_and_admin_acl(ctx):
    assert ctx["client"].get("/api/v1/products").status_code == 401
    assert ctx["client"].get("/api/v1/admin/users", headers={"Authorization": "Bearer bogus"}).status_code == 401
    _, auth = setup(ctx)
    assert ctx["client"].post("/api/v1/admin/codes/batch", headers=auth, json={
        "product_id": P_ID, "duration_days": 30, "count": 1}).status_code == 403
    assert ctx["client"].get("/api/v1/admin/users", headers=auth).status_code == 403
    assert ctx["client"].post("/api/v1/trials/start", headers=ctx["admin"], json={
        "product_id": P_ID}).status_code == 403


def test_cross_account_access_blocked(ctx):
    _, auth = setup(ctx)
    lic = activation(ctx, auth, issue(ctx)[0]).json()
    other_user = ctx["client"].post("/api/v1/admin/users", headers=ctx["admin"],
          json={"account_identifier": "second@example.invalid"}).json()["user_id"]
    token = ctx["client"].post("/api/v1/admin/tokens", headers=ctx["admin"],
          json={"user_id": other_user}).json()["token"]
    other = {"Authorization": f"Bearer {token}"}
    assert ctx["client"].get(f"/api/v1/licenses/{lic['license_id']}", headers=other).status_code == 404
    assert validation(ctx, other, lic["license_id"]).status_code == 404
    assert ctx["client"].post("/api/v1/licenses/revoke", headers=other,
         json={"license_id": lic["license_id"]}).status_code == 404


def test_rate_limit(ctx):
    _, auth = setup(ctx)
    lic = activation(ctx, auth, issue(ctx)[0]).json()
    for _ in range(60):
        assert validation(ctx, auth, lic["license_id"]).status_code == 200
    assert validation(ctx, auth, lic["license_id"]).status_code == 429
    ctx["clock"][0] = NOW + timedelta(minutes=1)
    assert validation(ctx, auth, lic["license_id"]).status_code == 200


def test_device_registration_explicitly_unverified(ctx):
    _, auth = setup(ctx)
    lic = activation(ctx, auth, issue(ctx)[0]).json()
    dev = ctx["client"].post("/api/v1/devices/register", headers=auth,
         json={"product_id": P_ID})
    assert dev.status_code == 200, dev.text
    assert dev.json()["status"] == "unverified"
    assert validation(ctx, auth, lic["license_id"], dev.json()["device_id"]).json()["device_registration_status"] == "unverified"
    assert ctx["client"].post(f"/api/v1/admin/devices/{dev.json()['device_id']}/revoke",
         headers=ctx["admin"]).status_code == 200
    assert validation(ctx, auth, lic["license_id"], dev.json()["device_id"]).json()["device_registration_status"] == "revoked"


def test_admin_extension_and_history(ctx):
    _, auth = setup(ctx)
    lic = activation(ctx, auth, issue(ctx)[0]).json()
    r = ctx["client"].post(f"/api/v1/admin/licenses/{lic['license_id']}/extend",
         headers=ctx["admin"], json={"days": 30})
    assert r.status_code == 200, r.text
    assert r.json()["expires_at"] == "2027-01-19T10:00:00+00:00"
    events = ctx["client"].get("/api/v1/admin/events", headers=ctx["admin"]).json()
    assert "admin_extension" in {e["event_type"] for e in events}
    assert ctx["client"].get("/api/v1/admin/licenses", headers=ctx["admin"]).status_code == 200
    assert ctx["client"].get("/api/v1/admin/users", headers=ctx["admin"]).status_code == 200


def test_transaction_rollback_after_claim(ctx, monkeypatch):
    _, auth = setup(ctx)
    code = issue(ctx)[0]
    import project_x.server.service as service_mod
    original = service_mod.LicenseService._claim_code

    def break_after_claim(self, code_text, product_id, user_id):
        original(self, code_text, product_id, user_id)
        raise RuntimeError("Simulated failure after atomic code update")

    monkeypatch.setattr(service_mod.LicenseService, "_claim_code", break_after_claim)
    from fastapi.testclient import TestClient
    with TestClient(ctx["app"], raise_server_exceptions=False) as tempclient:
        fail = tempclient.post("/api/v1/licenses/activate", headers=auth,
                               json={"product_id": P_ID, "activation_code": code})
        assert fail.status_code == 500
    monkeypatch.setattr(service_mod.LicenseService, "_claim_code", original)
    assert activation(ctx, auth, code).status_code == 200


def test_parallel_activation_single_winner(ctx):
    _, auth = setup(ctx)
    code = issue(ctx)[0]
    def call(_):
        with TestClient(ctx["app"]) as client:
            return client.post("/api/v1/licenses/activate", headers=auth,
                json={"product_id": P_ID, "activation_code": code}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(call, range(2)))
    assert sorted(results) == [200, 409]


def test_admin_approval_revocation_disables_features(ctx):
    _, auth = setup(ctx)
    lic = activation(ctx, auth, issue(ctx)[0]).json()
    r = ctx["client"].patch(f"/api/v1/admin/products/{P_ID}", headers=ctx["admin"],
         json={"status": "blocked"})
    assert r.status_code == 200
    val = validation(ctx, auth, lic["license_id"]).json()
    assert val["license_status"] == "product_unavailable"
    assert val["available_features"] == []


def test_no_secret_codes_in_db(ctx):
    _, auth = setup(ctx)
    code = issue(ctx)[0]
    activation(ctx, auth, code)
    with Session(ctx["app"].state.engine) as db:
        rows = db.scalars(select(ActivationCode)).all()
        assert len(rows) == 1
        assert rows[0].code_hash == fingerprint(ctx["settings"].code_pepper, code)
        assert code != rows[0].code_hash
        assert all(code not in str(event.details) for event in db.scalars(select(LicenseEvent)).all())


def test_get_expired_license_reads_correct_status(ctx):
    _, auth = setup(ctx)
    lic = activation(ctx, auth, issue(ctx)[0]).json()
    ctx["clock"][0] = NOW + timedelta(days=30)
    r = ctx["client"].get(f"/api/v1/licenses/{lic['license_id']}", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "expired"


def test_admin_customer_suspension_and_token_revocation(ctx):
    user_id, auth = setup(ctx)
    assert ctx["client"].get("/api/v1/products", headers=auth).status_code == 200
    suspended = ctx["client"].post(f"/api/v1/admin/users/{user_id}/suspend", headers=ctx["admin"])
    assert suspended.status_code == 200
    assert ctx["client"].get("/api/v1/products", headers=auth).status_code == 403
    with Session(ctx["app"].state.engine) as db:
        token = db.scalar(select(ApiToken).where(ApiToken.user_id == user_id))
        token_id = token.id
    assert ctx["client"].post(f"/api/v1/admin/tokens/{token_id}/revoke", headers=ctx["admin"]).status_code == 200
    assert ctx["client"].get("/api/v1/products", headers=auth).status_code == 401


def test_admin_code_history_excludes_secrets(ctx):
    _, auth = setup(ctx)
    code = issue(ctx)[0]
    activation(ctx, auth, code)
    r = ctx["client"].get("/api/v1/admin/codes", headers=ctx["admin"])
    assert r.status_code == 200
    assert r.json()[0]["status"] == "redeemed"
    assert "code_hash" not in r.text
    assert code not in r.text
    assert ctx["client"].get("/api/v1/admin/codes", headers=auth).status_code == 403


def test_input_validation_prevents_unknown_fields(ctx):
    _, auth = setup(ctx)
    r = ctx["client"].post("/api/v1/licenses/activate", headers=auth, json={
        "product_id": P_ID, "activation_code": "x" * 32, "user_id": "attacker"})
    assert r.status_code == 422
    r = ctx["client"].post("/api/v1/admin/codes/batch", headers=ctx["admin"], json={
        "product_id": P_ID, "duration_days": 29, "count": 1})
    assert r.status_code == 422
