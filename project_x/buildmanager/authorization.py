"""Fail-closed execution-permit gate for future build-manager work.

Preflight only checks an *unsigned* owner declaration and remains advisory.
This module is the separate, explicit authorization gate: without an injected
verifier nothing is authorized. A valid result yields a dry-run-only permit that
still cannot execute anything; this repository has no executor and no signing
key. Verifiers are supplied by the caller (tests use a local fixture verifier).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .preflight import AuthorizationManifest, PreflightInputError

RECOGNIZED_VERIFICATION_METHODS = frozenset({"fixture-detached-signature-v1"})
ALLOWED_SIGNERS = frozenset({"owner-owned-test-fixture"})
ALLOWED_PROVENANCE = frozenset({"local-owned-demo-build"})

# Fixed rejection codes. No verifier output, manifest value, path or exception
# text is ever included in an error.
VERIFIER_REQUIRED = "AUTHORIZATION_VERIFIER_REQUIRED"
MANIFEST_INVALID = "MANIFEST_INVALID"
VERIFIER_FAILED = "AUTHORIZATION_VERIFIER_FAILED"
UNVERIFIED = "AUTHORIZATION_NOT_VERIFIED"
UNKNOWN_METHOD = "VERIFICATION_METHOD_UNKNOWN"
ARTIFACT_MISMATCH = "ARTIFACT_HASH_NOT_BOUND"
UNKNOWN_SIGNER = "SIGNER_NOT_ALLOWED"
UNKNOWN_PROVENANCE = "PROVENANCE_NOT_ALLOWED"
AUTHORIZATION_ID_MISMATCH = "AUTHORIZATION_ID_NOT_BOUND"

_FIXED_CODES = frozenset(
    {
        VERIFIER_REQUIRED,
        MANIFEST_INVALID,
        VERIFIER_FAILED,
        UNVERIFIED,
        UNKNOWN_METHOD,
        ARTIFACT_MISMATCH,
        UNKNOWN_SIGNER,
        UNKNOWN_PROVENANCE,
        AUTHORIZATION_ID_MISMATCH,
    }
)


class AuthorizationVerificationError(ValueError):
    """Authorization was not proven; ``code`` is a fixed, value-free code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerificationResult:
    """The narrow result a caller-supplied verifier must produce.

    It carries no secret: signer and provenance are identifiers checked against
    the fixed allowlists above, and ``artifact_sha256`` binds the verification
    to the exact hash declared in the manifest.
    """

    cryptographically_verified: bool
    method: str
    artifact_sha256: str
    authorization_id: str
    signer: str
    provenance: str


@dataclass(frozen=True)
class ExecutionPermit:
    """A dry-run-only authorization record. It is not an execution capability."""

    method: str
    artifact_sha256: str
    authorization_id: str
    signer: str
    provenance: str
    dry_run_only: bool = True
    execution_permitted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "artifact_sha256": self.artifact_sha256,
            "authorization_id": self.authorization_id,
            "signer": self.signer,
            "provenance": self.provenance,
            "dry_run_only": self.dry_run_only,
            "execution_permitted": self.execution_permitted,
        }


def require_execution_permit(
    manifest: dict,
    verifier: Callable[[dict], VerificationResult] | None = None,
) -> ExecutionPermit:
    """Require verified, allowlisted authorization before any future execution.

    The default (no verifier) always rejects. The unsigned manifest alone never
    authorizes execution. This function performs no I/O, signing, device access
    or subprocess work.
    """
    if verifier is None:
        raise AuthorizationVerificationError(VERIFIER_REQUIRED)

    try:
        auth = AuthorizationManifest.from_dict(manifest)
    except PreflightInputError:
        raise AuthorizationVerificationError(MANIFEST_INVALID) from None

    try:
        result = verifier(dict(manifest))
    except AuthorizationVerificationError as exc:
        # A verifier may raise only one of this module's fixed codes. Anything
        # else can contain a path or secret, so reduce it to the generic code.
        code = exc.code if isinstance(exc.code, str) and exc.code in _FIXED_CODES else VERIFIER_FAILED
        raise AuthorizationVerificationError(code) from None
    except Exception:
        # Verifier exception text may contain paths or secrets; discard it.
        raise AuthorizationVerificationError(VERIFIER_FAILED) from None

    if not isinstance(result, VerificationResult):
        raise AuthorizationVerificationError(VERIFIER_FAILED)
    if result.cryptographically_verified is not True:
        raise AuthorizationVerificationError(UNVERIFIED)
    if not isinstance(result.method, str) or result.method not in RECOGNIZED_VERIFICATION_METHODS:
        raise AuthorizationVerificationError(UNKNOWN_METHOD)
    if not isinstance(result.artifact_sha256, str) or result.artifact_sha256 != auth.expected_sha256:
        raise AuthorizationVerificationError(ARTIFACT_MISMATCH)
    if not isinstance(result.authorization_id, str) or result.authorization_id != auth.authorization_id:
        raise AuthorizationVerificationError(AUTHORIZATION_ID_MISMATCH)
    if not isinstance(result.signer, str) or result.signer not in ALLOWED_SIGNERS:
        raise AuthorizationVerificationError(UNKNOWN_SIGNER)
    if not isinstance(result.provenance, str) or result.provenance not in ALLOWED_PROVENANCE:
        raise AuthorizationVerificationError(UNKNOWN_PROVENANCE)

    return ExecutionPermit(
        method=result.method,
        artifact_sha256=result.artifact_sha256,
        authorization_id=result.authorization_id,
        signer=result.signer,
        provenance=result.provenance,
    )
