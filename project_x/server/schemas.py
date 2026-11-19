"""Strict Pydantic schemas for public and administrative operations."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Activate(StrictSchema):
    product_id: str = Field(min_length=1, max_length=100)
    activation_code: str = Field(min_length=16, max_length=256)


class Renew(StrictSchema):
    license_id: str = Field(min_length=1, max_length=36)
    activation_code: str = Field(min_length=16, max_length=256)


class Validate(StrictSchema):
    license_id: str = Field(min_length=1, max_length=36)
    device_id: str | None = Field(default=None, min_length=1, max_length=36)


class Revoke(StrictSchema):
    license_id: str = Field(min_length=1, max_length=36)


class TrialStart(StrictSchema):
    product_id: str = Field(min_length=1, max_length=100)


class AdminProduct(StrictSchema):
    product_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=160)
    bundle_id: str = Field(min_length=3, max_length=180)
    version: str = Field(min_length=1, max_length=64)
    features: list[str] = Field(default_factory=list, max_length=100)
    status: Literal["blocked", "available"] = "blocked"
    rights_reference: str | None = Field(default=None, max_length=300)


class ProductAvailability(StrictSchema):
    status: Literal["blocked", "available"]
    rights_reference: str | None = Field(default=None, max_length=300)


class AdminUser(StrictSchema):
    account_identifier: str = Field(min_length=3, max_length=254)


class IssueToken(StrictSchema):
    user_id: str = Field(min_length=1, max_length=36)


class IssueCodes(StrictSchema):
    product_id: str = Field(min_length=1, max_length=100)
    duration_days: int = Field(ge=1, le=3660)
    count: int = Field(default=1, ge=1, le=100)


class AdminExtend(StrictSchema):
    days: int = Field(ge=1, le=3660)


class LicenseRead(StrictSchema):
    license_id: str
    user_id: str
    product_id: str
    activated_at: datetime
    expires_at: datetime
    status: str


class ValidationResult(StrictSchema):
    license_status: str
    product_id: str
    expiration_timestamp: datetime
    available_features: list[str]
    device_registration_status: str
