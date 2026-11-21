"""Fail-closed verified-authorization gate tests.

All verifiers here are local fixtures. No signing key, secret, executor, device,
or network access is used, and no manifest on its own authorizes execution.
"""

from __future__ import annotations

import json

import pytest

from project_x.buildmanager import (
    ALLOWED_PROVENANCE,
    ALLOWED_SIGNERS,
    RECOGNIZED_VERIFICATION_METHODS,
    AuthorizationVerificationError,
    ExecutionPermit,
    VerificationResult,
    require_execution_permit,
)

MANIFEST = {
    "schema_version": "1.0",
    "owner_authorized": True,
    "authorization_id": "AUTH-DEMO-001",
    "expected_identity": {
        "bundle_id": "demo.owned",
        "version": "1.0.0",
        "build_number": "7",
    },
    "expected_sha256": "a" * 64,
    "rights_basis": "owned-test-package",
}


def valid_result(**overrides) -> VerificationResult:
    values = {
        "cryptographically_verified": True,
        "method": next(iter(RECOGNIZED_VERIFICATION_METHODS)),
        "artifact_sha256": MANIFEST["expected_sha256"],
        "authorization_id": MANIFEST["authorization_id"],
        "signer": next(iter(ALLOWED_SIGNERS)),
        "provenance": next(iter(ALLOWED_PROVENANCE)),
    }
    values.update(overrides)
    return VerificationResult(**values)


def verifier(result: VerificationResult):
    def _verify(manifest: dict) -> VerificationResult:
        assert manifest == MANIFEST
        return result

    return _verify


def rejection_code(callable_) -> str:
    with pytest.raises(AuthorizationVerificationError) as excinfo:
        callable_()
    assert excinfo.value.code == str(excinfo.value)
    return excinfo.value.code


def test_default_without_verifier_is_rejected() -> None:
    assert rejection_code(lambda: require_execution_permit(MANIFEST)) == (
        "AUTHORIZATION_VERIFIER_REQUIRED"
    )


def test_unsigned_or_forged_verification_is_rejected() -> None:
    code = rejection_code(
        lambda: require_execution_permit(
            MANIFEST, verifier(valid_result(cryptographically_verified=False))
        )
    )
    assert code == "AUTHORIZATION_NOT_VERIFIED"


def test_unknown_verification_method_is_rejected() -> None:
    code = rejection_code(
        lambda: require_execution_permit(MANIFEST, verifier(valid_result(method="magic")))
    )
    assert code == "VERIFICATION_METHOD_UNKNOWN"


def test_wrong_artifact_hash_is_rejected() -> None:
    code = rejection_code(
        lambda: require_execution_permit(
            MANIFEST, verifier(valid_result(artifact_sha256="b" * 64))
        )
    )
    assert code == "ARTIFACT_HASH_NOT_BOUND"


def test_unbound_authorization_id_is_rejected() -> None:
    code = rejection_code(
        lambda: require_execution_permit(
            MANIFEST, verifier(valid_result(authorization_id="AUTH-OTHER-001"))
        )
    )
    assert code == "AUTHORIZATION_ID_NOT_BOUND"


def test_unknown_signer_is_rejected() -> None:
    code = rejection_code(
        lambda: require_execution_permit(MANIFEST, verifier(valid_result(signer="stranger")))
    )
    assert code == "SIGNER_NOT_ALLOWED"


def test_unknown_provenance_is_rejected() -> None:
    code = rejection_code(
        lambda: require_execution_permit(
            MANIFEST, verifier(valid_result(provenance="untrusted-source"))
        )
    )
    assert code == "PROVENANCE_NOT_ALLOWED"


def test_verifier_exception_is_reduced_to_a_fixed_code() -> None:
    def exploding(_manifest: dict) -> VerificationResult:
        raise RuntimeError("C:\\Users\\owner\\private\\signing.key")

    code = rejection_code(lambda: require_execution_permit(MANIFEST, exploding))
    assert code == "AUTHORIZATION_VERIFIER_FAILED"
    assert "private" not in code


def test_verifier_raised_path_is_reduced_to_a_fixed_code() -> None:
    secret = "C:\\Users\\owner\\private\\signing.key"

    def leaking(_manifest: dict) -> VerificationResult:
        raise AuthorizationVerificationError(secret)

    with pytest.raises(AuthorizationVerificationError) as excinfo:
        require_execution_permit(MANIFEST, leaking)

    assert excinfo.value.code == "AUTHORIZATION_VERIFIER_FAILED"
    assert secret not in excinfo.value.code
    assert secret not in str(excinfo.value)


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        pytest.param("method", "VERIFICATION_METHOD_UNKNOWN", id="method"),
        pytest.param("signer", "SIGNER_NOT_ALLOWED", id="signer"),
        pytest.param("provenance", "PROVENANCE_NOT_ALLOWED", id="provenance"),
    ],
)
@pytest.mark.parametrize("value", [[], {}], ids=["list", "object"])
def test_unhashable_verifier_identity_fields_are_rejected(field: str, value, expected: str) -> None:
    code = rejection_code(
        lambda: require_execution_permit(MANIFEST, verifier(valid_result(**{field: value})))
    )
    assert code == expected


def test_invalid_manifest_is_rejected_even_with_a_verifier() -> None:
    manifest = dict(MANIFEST)
    manifest["owner_authorized"] = False
    code = rejection_code(
        lambda: require_execution_permit(manifest, verifier(valid_result()))
    )
    assert code == "MANIFEST_INVALID"


def test_valid_verifier_returns_dry_run_only_permit() -> None:
    before = json.dumps(MANIFEST, sort_keys=True)
    permit = require_execution_permit(MANIFEST, verifier(valid_result()))

    assert isinstance(permit, ExecutionPermit)
    assert permit.dry_run_only is True
    assert permit.execution_permitted is False
    assert not hasattr(permit, "execute")
    payload = permit.to_dict()
    assert payload["execution_permitted"] is False
    assert payload["dry_run_only"] is True
    assert payload["artifact_sha256"] == MANIFEST["expected_sha256"]
    assert json.dumps(MANIFEST, sort_keys=True) == before
