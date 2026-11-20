"""Read-only, fail-closed preflight tooling for future IPA integration work.

Nothing in this package builds, signs, repackages, installs, or launches an app.
The only output is a dry-run plan intended for independent review.
"""

from .preflight import (
    ALLOWED_BUNDLE_IDS,
    CORE_INSTALL_NAME,
    PLAN_SCHEMA_VERSION,
    AuthorizationManifest,
    Finding,
    PreflightInputError,
    PreflightResult,
    evaluate,
)

__all__ = [
    "ALLOWED_BUNDLE_IDS",
    "CORE_INSTALL_NAME",
    "PLAN_SCHEMA_VERSION",
    "AuthorizationManifest",
    "Finding",
    "PreflightInputError",
    "PreflightResult",
    "evaluate",
]
