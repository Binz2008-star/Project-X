"""Local-only prototype of independent trials and activation codes.

This is a domain component, NOT a public license API. Provisioning and
entitlement checks must be wrapped by authenticated, rate-limited endpoints
before any external use. It contains no Apple signing or third-party IPA code.
"""

from __future__ import annotations

import calendar
from contextlib import contextmanager
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

PLANS = {"monthly": 1, "quarterly": 3}
TRIAL_DAYS = 7


class LicenseError(ValueError):
    """Invalid activation, unapproved product, or repeated trial."""


def _utc(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware instant is required")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _stamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def _add_months(value: datetime, months: int) -> datetime:
    offset = (value.month - 1) + months
    year = value.year + offset // 12
    month = offset % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def _digest(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise LicenseError("A nonempty identifier or code is required")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class LicenseStore:
    """SQLite prototype. An installation ID is NOT proof of device identity."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        with self._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS products (
                    id TEXT PRIMARY KEY,
                    rights_status TEXT NOT NULL
                        CHECK (rights_status IN ('blocked', 'approved'))
                );
                CREATE TABLE IF NOT EXISTS codes (
                    code_digest TEXT PRIMARY KEY,
                    product_id TEXT NOT NULL REFERENCES products(id),
                    plan TEXT NOT NULL CHECK (plan IN ('monthly', 'quarterly')),
                    redeemed_at TEXT,
                    redeemed_installation_digest TEXT
                );
                CREATE TABLE IF NOT EXISTS grants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id TEXT NOT NULL REFERENCES products(id),
                    installation_digest TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('trial', 'monthly', 'quarterly')),
                    starts_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trials (
                    product_id TEXT NOT NULL REFERENCES products(id),
                    installation_digest TEXT NOT NULL,
                    PRIMARY KEY(product_id, installation_digest)
                );
                CREATE INDEX IF NOT EXISTS grants_lookup
                    ON grants(product_id, installation_digest, expires_at);
            """)

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA busy_timeout=10000")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _check_product(db: sqlite3.Connection, product_id: str) -> None:
        row = db.execute("SELECT rights_status FROM products WHERE id=?", (product_id,)).fetchone()
        if row is None or row["rights_status"] != "approved":
            raise LicenseError("Product is not approved for commercial activation")

    def register_product(self, product_id: str, rights_status: str = "blocked") -> None:
        """Offline operator action; approved requires separately verified rights."""
        if not product_id or rights_status not in {"blocked", "approved"}:
            raise LicenseError("Invalid product or rights status")
        with self._connection() as db:
            db.execute(
                "INSERT INTO products(id, rights_status) VALUES(?, ?) "
                "ON CONFLICT(id) DO UPDATE SET rights_status=excluded.rights_status",
                (product_id, rights_status),
            )

    def issue_code(self, product_id: str, plan: str) -> str:
        """Trusted operator only; returns secret exactly once, stores its hash."""
        if plan not in PLANS:
            raise LicenseError("Plan must be monthly or quarterly")
        code = secrets.token_urlsafe(24)
        with self._connection() as db:
            self._check_product(db, product_id)
            db.execute(
                "INSERT INTO codes(code_digest, product_id, plan) VALUES (?, ?, ?)",
                (_digest(code), product_id, plan),
            )
        return code

    def start_trial(self, product_id: str, installation_id: str, *, now: datetime | None = None) -> str:
        instant = _utc(now)
        identity = _digest(installation_id)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._check_product(db, product_id)
            try:
                db.execute(
                    "INSERT INTO trials(product_id, installation_digest) VALUES(?, ?)",
                    (product_id, identity),
                )
            except sqlite3.IntegrityError as exc:
                raise LicenseError("Trial already claimed for this installation") from exc
            expiry = _stamp(instant + timedelta(days=TRIAL_DAYS))
            db.execute(
                "INSERT INTO grants(product_id, installation_digest, kind, starts_at, expires_at) "
                "VALUES(?, ?, 'trial', ?, ?)",
                (product_id, identity, _stamp(instant), expiry),
            )
            return expiry

    def redeem(self, code: str, installation_id: str, *, now: datetime | None = None) -> str:
        instant = _utc(now)
        digest = _digest(code)
        identity = _digest(installation_id)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT product_id, plan, redeemed_at FROM codes WHERE code_digest=?", (digest,)
            ).fetchone()
            if row is None or row["redeemed_at"] is not None:
                raise LicenseError("Code is invalid or already redeemed")
            self._check_product(db, row["product_id"])
            latest = db.execute(
                "SELECT MAX(expires_at) AS expiry FROM grants "
                "WHERE product_id=? AND installation_digest=? AND expires_at>?",
                (row["product_id"], identity, _stamp(instant)),
            ).fetchone()["expiry"]
            start = max(instant, datetime.fromisoformat(latest)) if latest else instant
            expiry = _stamp(_add_months(start, PLANS[row["plan"]]))
            db.execute(
                "UPDATE codes SET redeemed_at=?, redeemed_installation_digest=? "
                "WHERE code_digest=? AND redeemed_at IS NULL",
                (_stamp(instant), identity, digest),
            )
            db.execute(
                "INSERT INTO grants(product_id, installation_digest, kind, starts_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (row["product_id"], identity, row["plan"], _stamp(start), expiry),
            )
            return expiry

    def entitlement(self, product_id: str, installation_id: str, *, now: datetime | None = None) -> dict:
        """Local status: true only for an approved product with an active grant."""
        instant = _stamp(_utc(now))
        with self._connection() as db:
            product = db.execute("SELECT rights_status FROM products WHERE id=?", (product_id,)).fetchone()
            if product is None or product["rights_status"] != "approved":
                return {"active": False, "expires_at": None}
            expiry = db.execute(
                "SELECT MAX(expires_at) AS expiry FROM grants WHERE product_id=? "
                "AND installation_digest=? AND starts_at<=? AND expires_at>?",
                (product_id, _digest(installation_id), instant, instant),
            ).fetchone()["expiry"]
            return {"active": expiry is not None, "expires_at": expiry}
