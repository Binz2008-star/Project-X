"""Read-only, fail-closed preflight tooling for future IPA integration work.

Nothing in this package builds, signs, repackages, installs, or launches an app.
The only output is a dry-run plan intended for independent review.
"""

from .authorization import (
    ALLOWED_PROVENANCE,
    ALLOWED_SIGNERS,
    RECOGNIZED_VERIFICATION_METHODS,
    AuthorizationVerificationError,
    ExecutionPermit,
    VerificationResult,
    require_execution_permit,
)
from .preflight import (
    ACCEPTED_REPORT_SCHEMA_VERSIONS,
    ALLOWED_BUNDLE_IDS,
    CORE_INSTALL_NAME,
    EXPECTED_SEVERITIES,
    PLAN_SCHEMA_VERSION,
    REPORT_INCONSISTENT_CODE,
    UNSAFE_IDENTITY_CODE,
    AuthorizationManifest,
    Finding,
    PreflightInputError,
    PreflightResult,
    evaluate,
)

__all__ = [
    "ACCEPTED_REPORT_SCHEMA_VERSIONS",
    "ALLOWED_BUNDLE_IDS",
    "ALLOWED_PROVENANCE",
    "ALLOWED_SIGNERS",
    "CORE_INSTALL_NAME",
    "EXPECTED_SEVERITIES",
    "PLAN_SCHEMA_VERSION",
    "RECOGNIZED_VERIFICATION_METHODS",
    "REPORT_INCONSISTENT_CODE",
    "UNSAFE_IDENTITY_CODE",
    "AuthorizationManifest",
    "AuthorizationVerificationError",
    "ExecutionPermit",
    "Finding",
    "PreflightInputError",
    "PreflightResult",
    "VerificationResult",
    "evaluate",
    "require_execution_permit",
]
