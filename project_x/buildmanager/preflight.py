"""Fail-closed preflight gate and dry-run plan generator.

Inputs are limited to two JSON documents:

* an owner authorization manifest; and
* an ``IpaInspectionReport`` (``schema_version`` 1.0) produced by the read-only
  analysis engine.

This module never opens an IPA, never extracts, writes, signs, or relocates a
bundle, never reads credentials, and never contacts a device or remote service.
A successful preflight produces a *plan for review* whose
``execution_permitted`` is always ``false``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

PLAN_SCHEMA_VERSION = "1.0"
REPORT_SCHEMA_VERSION = "1.0"
MANIFEST_SCHEMA_VERSION = "1.0"

CORE_INSTALL_NAME = "@rpath/libXinstaCore.dylib"
MINIMUM_IOS = (16, 3)
MINIMUM_IOS_TEXT = "16.3"

# This milestone only accepts an explicitly owned test package. Third-party
# application rights are not established (see docs/RIGHTS_REGISTER.md), so no
# third-party bundle identifier can pass this gate regardless of manifest text.
ALLOWED_BUNDLE_IDS = frozenset({"demo.owned"})
ALLOWED_RIGHTS_BASIS = frozenset({"owned-test-package"})
ALLOWED_ARCHITECTURES = frozenset({"arm64", "arm64e"})

# Finding codes emitted by the schema 1.0 read-only analyzer. Only these fixed
# literals may be copied into a preflight result; anything else is untrusted
# input and must never reach output (it could contain a path or a secret).
KNOWN_ANALYSIS_CODES = frozenset(
    {
        "ABSOLUTE_ENTRY_PATH",
        "ARCHIVE_TOO_LARGE",
        "BACKSLASH_ENTRY_PATH",
        "COMPRESSION_RATIO_ABNORMAL",
        "CORRUPT_ENTRY",
        "DUPLICATE_ENTRY_NAME",
        "EMPTY_ARCHIVE",
        "EMPTY_ENTRY_NAME",
        "ENCRYPTED_ENTRY",
        "ENTRY_READ_TOO_LARGE",
        "ENTRY_TOO_LARGE",
        "EXECUTABLE_NOT_PRESENT",
        "FAIRPLAY_METADATA_PRESENT",
        "FRAMEWORK_NAME_COLLISION",
        "MAIN_BINARY_DECRYPTED",
        "MAIN_BINARY_ENCRYPTED",
        "MAIN_BINARY_UNPARSEABLE",
        "MALFORMED_CENTRAL_DIRECTORY",
        "MH_BUNDLE",
        "MH_CORE",
        "MH_DYLIB",
        "MH_DYLIB_STUB",
        "MH_DYLINKER",
        "MH_EXECUTE",
        "MH_FVMLIB",
        "MH_KEXT_BUNDLE",
        "MH_OBJECT",
        "MH_PRELOAD",
        "MIN_OS_MISMATCH",
        "MISSING_BUNDLE_ID",
        "MISSING_EXECUTABLE_NAME",
        "NO_CODE_SIGNATURE",
        "NO_EMBEDDED_EXTENSIONS",
        "NON_ARM64_ARCHITECTURE",
        "NOT_A_ZIP",
        "NUL_IN_ENTRY_NAME",
        "PATH_TRAVERSAL",
        "PROTECTED_FRAMEWORK_BASENAMES",
        "PROVISIONING_PROFILE_PRESENT",
        "SYMLINK_ENTRY",
        "TOO_MANY_ENTRIES",
        "UNEXPECTED_EXTENSION_IDENTIFIER",
        "UNREADABLE_ARCHIVE",
        "UNRESOLVED_RPATH_DEPENDENCY",
        "UNSIGNED_NESTED_BUNDLE",
        "UNSUPPORTED_COMPRESSION",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_AUTHORIZATION_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?$")

_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "owner_authorized",
        "authorization_id",
        "expected_identity",
        "expected_sha256",
        "rights_basis",
    }
)
_IDENTITY_KEYS = frozenset({"bundle_id", "version", "build_number"})

_BLK = "blocker"
_WARN = "warning"


class PreflightInputError(ValueError):
    """The manifest or inspection report does not satisfy the input contract."""


@dataclass(frozen=True)
class Finding:
    """A stable, secret-free preflight result line."""

    code: str
    severity: str
    detail: str

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "detail": self.detail}


@dataclass(frozen=True)
class AuthorizationManifest:
    """Owner declaration that a specific, already-inspected package is eligible."""

    authorization_id: str
    bundle_id: str
    version: str
    build_number: str
    expected_sha256: str
    rights_basis: str

    @classmethod
    def from_dict(cls, value: Any) -> "AuthorizationManifest":
        data = _mapping(value, "manifest")
        if data.get("schema_version") != MANIFEST_SCHEMA_VERSION:
            raise PreflightInputError("manifest.schema_version must be '1.0'")
        keys = frozenset(data)
        if keys != _MANIFEST_KEYS:
            missing_count = len(_MANIFEST_KEYS - keys)
            unknown_count = len(keys - _MANIFEST_KEYS)
            # Never echo unknown key names: they are attacker-controlled and
            # could contain a path, a secret, or control characters.
            raise PreflightInputError(
                f"manifest keys must be exact (missing_count={missing_count}, "
                f"unknown_count={unknown_count})"
            )
        if data["owner_authorized"] is not True:
            raise PreflightInputError("manifest.owner_authorized must be boolean true")
        authorization_id = _string(data["authorization_id"], "manifest.authorization_id")
        if not _AUTHORIZATION_ID_RE.match(authorization_id):
            raise PreflightInputError("manifest.authorization_id has an invalid format")

        identity = _mapping(data["expected_identity"], "manifest.expected_identity")
        if frozenset(identity) != _IDENTITY_KEYS:
            raise PreflightInputError("manifest.expected_identity keys must be exact")
        bundle_id = _string(identity["bundle_id"], "manifest.expected_identity.bundle_id")
        version = _string(identity["version"], "manifest.expected_identity.version")
        build_number = _string(
            identity["build_number"], "manifest.expected_identity.build_number"
        )
        for field, text in (
            ("bundle_id", bundle_id),
            ("version", version),
            ("build_number", build_number),
        ):
            if any(token in text for token in ("*", "?", "..")):
                raise PreflightInputError(
                    f"manifest.expected_identity.{field} must be an exact value"
                )

        expected_sha256 = _string(data["expected_sha256"], "manifest.expected_sha256")
        if not _SHA256_RE.match(expected_sha256):
            raise PreflightInputError(
                "manifest.expected_sha256 must be 64 lower-case hex characters"
            )
        rights_basis = _string(data["rights_basis"], "manifest.rights_basis")
        if rights_basis not in ALLOWED_RIGHTS_BASIS:
            raise PreflightInputError("manifest.rights_basis is not allowed")

        return cls(
            authorization_id=authorization_id,
            bundle_id=bundle_id,
            version=version,
            build_number=build_number,
            expected_sha256=expected_sha256,
            rights_basis=rights_basis,
        )


@dataclass(frozen=True)
class PreflightResult:
    """Deterministic, JSON-serializable preflight outcome."""

    preflight_passed: bool
    findings: tuple[Finding, ...]
    plan: dict | None

    def to_dict(self) -> dict:
        return {
            "preflight_passed": self.preflight_passed,
            "findings": [f.to_dict() for f in self.findings],
            "plan": self.plan,
        }


def evaluate(manifest: Any, report: Any) -> PreflightResult:
    """Evaluate an authorization manifest against a versioned inspection report."""
    try:
        auth = AuthorizationManifest.from_dict(manifest)
    except PreflightInputError as exc:
        return _rejected([Finding("MANIFEST_INVALID", _BLK, str(exc))])

    try:
        _validate_report(report)
    except PreflightInputError as exc:
        return _rejected([Finding("REPORT_INVALID", _BLK, str(exc))])

    findings: list[Finding] = []
    identity = report["identity"]
    artifact = report["artifact"]

    if auth.bundle_id not in ALLOWED_BUNDLE_IDS:
        findings.append(
            Finding(
                "BUNDLE_ID_NOT_ALLOWED",
                _BLK,
                "only explicitly owned test packages are eligible in this milestone",
            )
        )
    if identity["bundle_id"] != auth.bundle_id:
        findings.append(Finding("BUNDLE_ID_MISMATCH", _BLK, "inspected bundle differs from manifest"))
    if identity["version"] != auth.version:
        findings.append(Finding("VERSION_MISMATCH", _BLK, "inspected version differs from manifest"))
    if identity["build_number"] != auth.build_number:
        findings.append(
            Finding("BUILD_MISMATCH", _BLK, "inspected build differs from manifest")
        )
    if str(artifact["sha256"]).lower() != auth.expected_sha256:
        findings.append(
            Finding("SHA256_MISMATCH", _BLK, "artifact hash differs from authorized hash")
        )

    minimum_os = identity["minimum_os"]
    if not _version_at_least(minimum_os, MINIMUM_IOS):
        findings.append(
            Finding(
                "MINIMUM_OS_TOO_LOW",
                _BLK,
                f"package deployment target must be at least iOS {MINIMUM_IOS_TEXT}",
            )
        )

    if not isinstance(identity["executable"], str) or not identity["executable"]:
        findings.append(Finding("MAIN_EXECUTABLE_MISSING", _BLK, "no main executable recorded"))
    slices = report["macho"]["slices"]
    if report["macho"]["slice_count"] != len(slices):
        findings.append(
            Finding(
                "MACHO_SLICE_COUNT_MISMATCH",
                _BLK,
                "declared slice count differs from recorded slices",
            )
        )
    _check_slices(slices, findings)

    analysis_findings = report["findings"]
    warning_codes = sorted({f["code"] for f in analysis_findings if f["severity"] == _WARN})
    critical_codes = sorted({f["code"] for f in analysis_findings if f["severity"] == "critical"})
    if critical_codes:
        findings.append(
            Finding(
                "CRITICAL_ANALYSIS_FINDING",
                _BLK,
                "analysis reported critical structural findings: " + ", ".join(critical_codes),
            )
        )
    if report["signing"]["verification"].get("verified") is not False:
        findings.append(
            Finding(
                "SIGNING_VERIFICATION_CLAIM",
                _BLK,
                "static analysis must never claim signature verification",
            )
        )
    if report["interpretation"]["malware_verdict"] is not None:
        findings.append(
            Finding(
                "MALWARE_VERDICT_CLAIM",
                _BLK,
                "static analysis must not emit a malware verdict",
            )
        )
    if report["dependencies"]["unresolved_rpath_dependencies"]:
        findings.append(
            Finding(
                "UNRESOLVED_RPATH_DEPENDENCY",
                _BLK,
                "unresolved @rpath dependencies must be reviewed before planning",
            )
        )
    if report["dependencies"]["duplicate_framework_basenames"]:
        warning_codes.append("DUPLICATE_FRAMEWORK_BASENAME")
    warning_codes = sorted(set(warning_codes))

    blockers = [f for f in findings if f.severity == _BLK]
    if blockers:
        return PreflightResult(False, tuple(findings), None)

    findings.append(
        Finding(
            "PREFLIGHT_PASSED",
            "info",
            "read-only preflight passed; execution remains prohibited in this plan",
        )
    )
    plan = _build_plan(auth, identity, artifact, warning_codes)
    return PreflightResult(True, tuple(findings), plan)


def _rejected(findings: list[Finding]) -> PreflightResult:
    return PreflightResult(False, tuple(findings), None)


def _mapping(value: Any, path: str) -> dict:
    if not isinstance(value, dict):
        raise PreflightInputError(f"{path} must be a JSON object")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise PreflightInputError(f"{path} must be a non-empty string")
    return value


def _version_at_least(value: Any, minimum: tuple[int, ...]) -> bool:
    if not isinstance(value, str):
        return False
    match = _VERSION_RE.match(value)
    if not match:
        return False
    parsed = tuple(int(part or 0) for part in match.groups())
    return parsed >= minimum


def _check_slices(slices: Any, findings: list[Finding]) -> None:
    if not isinstance(slices, list) or not slices:
        findings.append(
            Finding("MAIN_EXECUTABLE_SLICES_MISSING", _BLK, "no Mach-O slices recorded")
        )
        return
    seen: set[str] = set()
    for item in slices:
        if not isinstance(item, dict):
            _add_once(seen, findings, "MAIN_EXECUTABLE_SLICE_INVALID", _BLK, "malformed Mach-O slice")
            continue
        if item.get("arch") not in ALLOWED_ARCHITECTURES:
            _add_once(
                seen,
                findings,
                "MAIN_EXECUTABLE_ARCHITECTURE",
                _BLK,
                "only arm64-family main executables are supported",
            )
        if item.get("is_64_bit") is not True:
            _add_once(seen, findings, "MAIN_EXECUTABLE_NOT_64_BIT", _BLK, "slice is not 64-bit")
        if item.get("file_type") != "MH_EXECUTE":
            _add_once(seen, findings, "MAIN_EXECUTABLE_FILE_TYPE", _BLK, "slice is not MH_EXECUTE")
        encryption = item.get("encryption")
        cryptid = encryption.get("cryptid") if isinstance(encryption, dict) else None
        if not isinstance(cryptid, int) or isinstance(cryptid, bool) or cryptid != 0:
            _add_once(
                seen,
                findings,
                "MAIN_EXECUTABLE_ENCRYPTED",
                _BLK,
                "encrypted or unknown main executable cannot be planned safely",
            )


def _add_once(
    seen: set[str], findings: list[Finding], code: str, severity: str, detail: str
) -> None:
    if code not in seen:
        seen.add(code)
        findings.append(Finding(code, severity, detail))


def _validate_report(report: Any) -> None:
    data = _mapping(report, "report")
    if data.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise PreflightInputError("report.schema_version must be '1.0'")

    identity = _mapping(data.get("identity"), "report.identity")
    for key in _IDENTITY_KEYS | {"minimum_os", "executable"}:
        if key not in identity:
            raise PreflightInputError(f"report.identity.{key} is required")
    for key in ("bundle_id", "version", "build_number", "minimum_os", "executable"):
        if identity[key] is not None and not isinstance(identity[key], str):
            raise PreflightInputError(f"report.identity.{key} must be a string or null")

    artifact = _mapping(data.get("artifact"), "report.artifact")
    if not isinstance(artifact.get("sha256"), str) or not _SHA256_RE.match(artifact["sha256"]):
        raise PreflightInputError("report.artifact.sha256 must be 64 lower-case hex characters")

    macho = _mapping(data.get("macho"), "report.macho")
    if "slices" not in macho:
        raise PreflightInputError("report.macho.slices is required")
    if "slice_count" not in macho:
        raise PreflightInputError("report.macho.slice_count is required")
    if not isinstance(macho["slice_count"], int) or isinstance(macho["slice_count"], bool):
        raise PreflightInputError("report.macho.slice_count must be an integer")

    analysis = data.get("findings")
    if not isinstance(analysis, list):
        raise PreflightInputError("report.findings must be a list")
    for item in analysis:
        entry = _mapping(item, "report.findings[]")
        code = entry.get("code")
        if not isinstance(code, str) or code not in KNOWN_ANALYSIS_CODES:
            raise PreflightInputError("report.findings[] has an unknown finding code")
        if entry.get("severity") not in {"critical", "warning", "info"}:
            raise PreflightInputError("report.findings[] has an invalid severity")

    signing = _mapping(data.get("signing"), "report.signing")
    _mapping(signing.get("verification"), "report.signing.verification")
    interpretation = _mapping(data.get("interpretation"), "report.interpretation")
    if "malware_verdict" not in interpretation:
        raise PreflightInputError("report.interpretation.malware_verdict is required")
    dependencies = _mapping(data.get("dependencies"), "report.dependencies")
    for key in ("unresolved_rpath_dependencies", "duplicate_framework_basenames"):
        if not isinstance(dependencies.get(key), list):
            raise PreflightInputError(f"report.dependencies.{key} must be a list")


def _build_plan(
    auth: AuthorizationManifest,
    identity: dict,
    artifact: dict,
    warning_codes: list[str],
) -> dict:
    """Produce a deterministic plan; no step in it is executable by this tool."""
    return {
        "plan_version": PLAN_SCHEMA_VERSION,
        "mode": "dry_run",
        "execution_permitted": False,
        "status": "READY_FOR_INDEPENDENT_REVIEW",
        "authorization": {
            "authorization_id": auth.authorization_id,
            "rights_basis": auth.rights_basis,
        },
        "package": {
            "bundle_id": identity["bundle_id"],
            "version": identity["version"],
            "build_number": identity["build_number"],
            "sha256": artifact["sha256"].lower(),
        },
        "xinsta_core": {
            "install_name": CORE_INSTALL_NAME,
            "load_entry": "XinstaCoreLoad",
            "compatibility_adapter": "not_applicable_to_owned_test_package",
            "hook": False,
            "swizzle": False,
        },
        "steps": [
            {
                "id": "verify_report_schema",
                "status": "passed",
                "action": "validated the versioned read-only inspection report",
            },
            {
                "id": "verify_owner_authorization",
                "status": "passed",
                "action": "matched the owner manifest to the inspected package and hash",
            },
            {
                "id": "stage_core_dylib",
                "status": "planned",
                "action": "would place the validated dylib in a Frameworks directory",
                "requires": ["separate_installer_review"],
            },
            {
                "id": "resolve_loader_rpath",
                "status": "planned",
                "action": "would add a host LC_RPATH or load by explicit path",
                "requires": ["separate_installer_review"],
            },
            {
                "id": "codesign_bundle_and_frameworks",
                "status": "blocked",
                "action": "would re-sign the bundle and all nested frameworks",
                "requires": ["signing_identity", "provisioning_profile"],
            },
            {
                "id": "register_device_and_install",
                "status": "blocked",
                "action": "would register a device and install the private build",
                "requires": ["registered_udid", "owner_device_authorization"],
            },
            {
                "id": "verify_x_settings_in_host",
                "status": "blocked",
                "action": "would verify X Settings inside the target application",
                "requires": ["approved_hook_path", "physical_device_qa"],
            },
        ],
        "required_credentials": [
            {"name": name, "provided": False, "secret": True}
            for name in (
                "signing_identity",
                "provisioning_profile",
                "registered_udid",
            )
        ],
        "review_findings": warning_codes,
        "limitations": [
            "no IPA is opened, extracted, modified, signed, or installed by this tool",
            "no hook, swizzle, injection method, or host executable change is validated",
            "static inspection is not a malware verdict or a signature verification",
        ],
    }
