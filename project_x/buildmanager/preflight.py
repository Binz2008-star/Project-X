"""Fail-closed preflight gate and dry-run plan generator.

Inputs are limited to two JSON documents:

* an unsigned owner declaration manifest (advisory only); and
* an ``IpaInspectionReport`` (``schema_version`` 1.0) produced by the read-only
  analysis engine.

This module never opens an IPA, never extracts, writes, signs, or relocates a
bundle, never reads credentials, and never contacts a device or remote service.
A successful preflight produces a *plan for review* whose
``execution_permitted`` is always ``false``.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

PLAN_SCHEMA_VERSION = "1.0"
MANIFEST_SCHEMA_VERSION = "1.0"
# Report 1.1 adds typed dependency references and fix codes; the consumed
# fields are unchanged, so both versions are accepted with the same checks.
ACCEPTED_REPORT_SCHEMA_VERSIONS = frozenset({"1.0", "1.1"})

CORE_INSTALL_NAME = "@rpath/libXinstaCore.dylib"
MINIMUM_IOS = (16, 3)
MINIMUM_IOS_TEXT = "16.3"

# This milestone accepts an explicitly owned test package, plus one narrowly
# pinned load-only proof identity authorised by the owner for this exact
# artifact. Third-party application rights are not established for commercial
# use (see docs/RIGHTS_REGISTER.md); the exception below is a dry-run planning
# allowance only. It does not permit a hook, signing, installation, device
# action, merge, or execution by this tool.
OWNED_TEST_RIGHTS_BASIS = "owned-test-package"
LOAD_ONLY_PROOF_RIGHTS_BASIS = "load-only-proof"
LOAD_ONLY_PROOF_IDENTITY = ("com.burbn.instagram", "456.0.0", "1114925422")
LOAD_ONLY_PROOF_SHA256 = (
    "665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131"
)
LOAD_ONLY_PROOF_ADAPTER = "com.burbn.instagram@456.0.0@1114925422"
ALLOWED_BUNDLE_IDS = frozenset({"demo.owned"})
ALLOWED_RIGHTS_BASIS = frozenset({OWNED_TEST_RIGHTS_BASIS, LOAD_ONLY_PROOF_RIGHTS_BASIS})
ALLOWED_ARCHITECTURES = frozenset({"arm64", "arm64e"})

# Bounded, output-safe identity text. Rejections are reported with fixed codes
# and never include the rejected value.
MAX_IDENTITY_TEXT_LENGTH = 256
UNSAFE_IDENTITY_CODE = "UNSAFE_IDENTITY_STRING"
REPORT_INCONSISTENT_CODE = "REPORT_INCONSISTENT"
_SECRET_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
)
_PATH_SEPARATORS = ("/", "\\")
_BIDI_RANGES = (
    ("\u200e", "\u200f"),
    ("\u202a", "\u202e"),
    ("\u2066", "\u2069"),
    ("\ufeff", "\ufeff"),
)

# Legacy alias used by older Mach-O producers; CPU subtype 1 is the same
# arm64v8 family member. Both are normalised to the canonical ``arm64`` name.
ARCH_ALIASES = frozenset({"arm64v8"})
ARM64_SUBTYPE_NAMES = {0: "arm64", 1: "arm64", 2: "arm64e"}

# Expected severity for every code the read-only analyzer can emit. The report
# never supplies the trusted severity: it is recomputed from this map and a
# mismatch fails closed with REPORT_INCONSISTENT. Raw finding context is ignored.
EXPECTED_SEVERITIES: dict[str, str] = {
    "ABSOLUTE_ENTRY_PATH": "critical",
    "AMBIGUOUS_APPLICATION_ROOT": "critical",
    "ARCHIVE_CHANGED_DURING_ANALYSIS": "critical",
    "ARCHIVE_TOO_LARGE": "critical",
    "BACKSLASH_ENTRY_PATH": "critical",
    "COMPRESSION_RATIO_ABNORMAL": "critical",
    "CORRUPT_ENTRY": "critical",
    "DUPLICATE_ENTRY_NAME": "warning",
    "EMPTY_ARCHIVE": "critical",
    "EMPTY_ENTRY_NAME": "critical",
    "ENCRYPTED_ENTRY": "critical",
    "ENTRY_READ_TOO_LARGE": "critical",
    "ENTRY_TOO_LARGE": "critical",
    "EXECUTABLE_NOT_PRESENT": "critical",
    "FAIRPLAY_METADATA_PRESENT": "info",
    "FRAMEWORK_NAME_COLLISION": "warning",
    "INVALID_INFO_PLIST_VALUE": "critical",
    "MAIN_BINARY_DECRYPTED": "info",
    "MAIN_BINARY_ENCRYPTED": "warning",
    "MAIN_BINARY_UNPARSEABLE": "critical",
    "MALFORMED_CENTRAL_DIRECTORY": "critical",
    "MH_BUNDLE": "critical",
    "MH_CORE": "critical",
    "MH_DYLIB": "critical",
    "MH_DYLIB_STUB": "critical",
    "MH_DYLINKER": "critical",
    "MH_EXECUTE": "info",
    "MH_FVMLIB": "critical",
    "MH_KEXT_BUNDLE": "critical",
    "MH_OBJECT": "critical",
    "MH_PRELOAD": "critical",
    "MIN_OS_MISMATCH": "warning",
    "MISSING_BUNDLE_ID": "critical",
    "MISSING_EXECUTABLE_NAME": "critical",
    "NO_CODE_SIGNATURE": "warning",
    "NO_EMBEDDED_EXTENSIONS": "info",
    "NON_ARM64_ARCHITECTURE": "warning",
    "NOT_A_ZIP": "critical",
    "NUL_IN_ENTRY_NAME": "critical",
    "PATH_TRAVERSAL": "critical",
    "PROTECTED_FRAMEWORK_BASENAMES": "info",
    "PROVISIONING_PROFILE_PRESENT": "info",
    "PROVISIONING_PROFILE_UNREADABLE": "warning",
    "SYMLINK_ENTRY": "warning",
    "TOO_MANY_ENTRIES": "critical",
    "UNEXPECTED_EXTENSION_IDENTIFIER": "warning",
    "UNREADABLE_ARCHIVE": "critical",
    "UNRESOLVED_RPATH_DEPENDENCY": "critical",
    "UNSIGNED_NESTED_BUNDLE": "warning",
    "UNSUPPORTED_COMPRESSION": "critical",
    "WEAK_UNRESOLVED_RPATH_DEPENDENCY": "warning",
}
KNOWN_ANALYSIS_CODES = frozenset(EXPECTED_SEVERITIES)

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


class UnsafeIdentityError(PreflightInputError):
    """A copied identity-like string failed the bounded, output-safe check."""


class ReportInconsistentError(PreflightInputError):
    """A report finding severity disagrees with its known finding code."""


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
        authorization_id = _safe_text(data["authorization_id"], "manifest.authorization_id")
        if not _AUTHORIZATION_ID_RE.match(authorization_id):
            raise PreflightInputError("manifest.authorization_id has an invalid format")

        identity = _mapping(data["expected_identity"], "manifest.expected_identity")
        if frozenset(identity) != _IDENTITY_KEYS:
            raise PreflightInputError("manifest.expected_identity keys must be exact")
        bundle_id = _safe_text(identity["bundle_id"], "manifest.expected_identity.bundle_id")
        version = _safe_text(identity["version"], "manifest.expected_identity.version")
        build_number = _safe_text(
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

        expected_sha256 = _safe_text(data["expected_sha256"], "manifest.expected_sha256")
        if not _SHA256_RE.match(expected_sha256):
            raise PreflightInputError(
                "manifest.expected_sha256 must be 64 lower-case hex characters"
            )
        rights_basis = _safe_text(data["rights_basis"], "manifest.rights_basis")
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
    except UnsafeIdentityError:
        return _rejected(
            [
                Finding(
                    UNSAFE_IDENTITY_CODE,
                    _BLK,
                    "manifest contains an unsafe identity-like value",
                )
            ]
        )
    except PreflightInputError as exc:
        return _rejected([Finding("MANIFEST_INVALID", _BLK, str(exc))])

    try:
        _validate_report(report)
    except UnsafeIdentityError:
        return _rejected(
            [
                Finding(
                    UNSAFE_IDENTITY_CODE,
                    _BLK,
                    "report contains an unsafe identity-like value",
                )
            ]
        )
    except ReportInconsistentError:
        return _rejected(
            [
                Finding(
                    REPORT_INCONSISTENT_CODE,
                    _BLK,
                    "report finding severity disagrees with the known finding code",
                )
            ]
        )
    except PreflightInputError as exc:
        return _rejected([Finding("REPORT_INVALID", _BLK, str(exc))])

    findings: list[Finding] = []
    identity = report["identity"]
    artifact = report["artifact"]
    load_only_proof = (
        auth.bundle_id,
        auth.version,
        auth.build_number,
    ) == LOAD_ONLY_PROOF_IDENTITY

    if auth.bundle_id not in ALLOWED_BUNDLE_IDS and not load_only_proof:
        findings.append(
            Finding(
                "BUNDLE_ID_NOT_ALLOWED",
                _BLK,
                "only explicitly owned test packages and the pinned load proof are eligible",
            )
        )
    if load_only_proof:
        if auth.rights_basis != LOAD_ONLY_PROOF_RIGHTS_BASIS:
            findings.append(
                Finding(
                    "RIGHTS_BASIS_NOT_ALLOWED_FOR_LOAD_PROOF",
                    _BLK,
                    "the pinned proof requires the load-only rights basis",
                )
            )
        if auth.expected_sha256 != LOAD_ONLY_PROOF_SHA256:
            findings.append(
                Finding(
                    "SHA256_NOT_PINNED_FOR_LOAD_PROOF",
                    _BLK,
                    "the pinned proof requires its recorded artifact hash",
                )
            )
    elif auth.rights_basis != OWNED_TEST_RIGHTS_BASIS:
        findings.append(
            Finding(
                "RIGHTS_BASIS_NOT_ALLOWED_FOR_OWNED_TEST",
                _BLK,
                "owned test packages require the owned-test rights basis",
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
    warning_codes = sorted(
        {f["code"] for f in analysis_findings if EXPECTED_SEVERITIES[f["code"]] == _WARN}
    )
    critical_codes = sorted(
        {f["code"] for f in analysis_findings if EXPECTED_SEVERITIES[f["code"]] == "critical"}
    )
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
    plan = _build_plan(auth, identity, artifact, warning_codes, load_only_proof)
    return PreflightResult(True, tuple(findings), plan)


def _rejected(findings: list[Finding]) -> PreflightResult:
    return PreflightResult(False, tuple(findings), None)


def _mapping(value: Any, path: str) -> dict:
    if not isinstance(value, dict):
        raise PreflightInputError(f"{path} must be a JSON object")
    return value


def _safe_text(value: Any, path: str) -> str:
    """Validate copied identity-like text without ever returning it in an error.

    Every rejection is a fixed code at the call site; the exception message only
    names the field, never the rejected value.
    """
    if not isinstance(value, str) or not value:
        raise PreflightInputError(f"{path} must be a non-empty string")
    if len(value) > MAX_IDENTITY_TEXT_LENGTH:
        raise UnsafeIdentityError(f"{path} is too long")
    folded = value.lower()
    if any(token in folded for token in _PATH_SEPARATORS):
        raise UnsafeIdentityError(f"{path} contains a path separator")
    if any(start <= char <= end for char in value for start, end in _BIDI_RANGES):
        raise UnsafeIdentityError(f"{path} contains a bidi control")
    for char in value:
        if unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}:
            raise UnsafeIdentityError(f"{path} contains a control character")
    if any(token in folded for token in _SECRET_MARKERS):
        raise UnsafeIdentityError(f"{path} looks like a secret")
    return value


def _normalise_arch(slice_record: dict) -> str | None:
    """Return the canonical arm64-family name or None when the slice is unsafe."""
    arch = slice_record.get("arch")
    if not isinstance(arch, str) or not arch:
        return None
    candidate = arch.strip().lower()
    # A subtype only refines an arm64-family declaration; it must never turn an
    # explicitly unsupported architecture into an accepted one.
    if candidate in ALLOWED_ARCHITECTURES or candidate in ARCH_ALIASES:
        subtype = slice_record.get("cpu_subtype")
        if isinstance(subtype, int) and not isinstance(subtype, bool):
            mapped = ARM64_SUBTYPE_NAMES.get(subtype & 0xFF)
            if mapped is not None:
                candidate = mapped
    if candidate in ARCH_ALIASES:
        candidate = "arm64"
    return candidate if candidate in ALLOWED_ARCHITECTURES else None


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
        if _normalise_arch(item) is None:
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
    schema_version = data.get("schema_version")
    if (
        not isinstance(schema_version, str)
        or schema_version not in ACCEPTED_REPORT_SCHEMA_VERSIONS
    ):
        raise PreflightInputError("report.schema_version is not allowlisted")

    identity = _mapping(data.get("identity"), "report.identity")
    for key in _IDENTITY_KEYS | {"minimum_os", "executable"}:
        if key not in identity:
            raise PreflightInputError(f"report.identity.{key} is required")
    for key in ("bundle_id", "version", "build_number", "minimum_os"):
        if identity[key] is not None:
            _safe_text(identity[key], f"report.identity.{key}")
    for key in ("name", "display_name"):
        if identity.get(key) is not None:
            _safe_text(identity[key], f"report.identity.{key}")
    # CFBundleExecutable is a bundle-relative path by design; it is never copied
    # into plan output, but it still gets the control/bidi/secret checks.
    if identity["executable"] is not None:
        executable = identity["executable"]
        if not isinstance(executable, str) or not executable:
            raise PreflightInputError("report.identity.executable must be a string or null")
        _safe_text(executable.replace("/", "").replace("\\", ""), "report.identity.executable")

    artifact = _mapping(data.get("artifact"), "report.artifact")
    if isinstance(artifact.get("sha256"), str):
        _safe_text(artifact["sha256"], "report.artifact.sha256")
    if not isinstance(artifact.get("sha256"), str) or not _SHA256_RE.match(artifact["sha256"]):
        raise PreflightInputError("report.artifact.sha256 must be 64 lower-case hex characters")

    macho = _mapping(data.get("macho"), "report.macho")
    if "slices" not in macho:
        raise PreflightInputError("report.macho.slices is required")
    if not isinstance(macho["slices"], list):
        raise PreflightInputError("report.macho.slices must be a list")
    for slice_item in macho["slices"]:
        _mapping(slice_item, "report.macho.slices[]")
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
        # The report's severity and context are untrusted; never copy either.
        if entry.get("severity") != EXPECTED_SEVERITIES[code]:
            raise ReportInconsistentError("report.findings[] severity is inconsistent")

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
    load_only_proof: bool,
) -> dict:
    """Produce a deterministic plan; no step in it is executable by this tool."""
    steps = [
        {
            "id": "verify_report_schema",
            "status": "passed",
            "action": "validated the versioned read-only inspection report",
        },
        {
            "id": "check_owner_declaration",
            "status": "passed",
            "action": (
                "matched the unsigned owner declaration to the inspected package "
                "and hash; this is not proof of authorization"
            ),
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
    ]
    if load_only_proof:
        steps.append(
            {
                "id": "verify_core_load_in_host",
                "status": "blocked",
                "action": "would collect the fixed constructor load marker on the authorized device",
                "requires": ["owner_runtime_scope", "authorized_device", "secure_signing_inputs"],
            }
        )

    limitations = [
        "no IPA is opened, extracted, modified, signed, or installed by this tool",
        "no hook, swizzle, injection method, or host executable change is validated",
        "static inspection is not a malware verdict or a signature verification",
        "the unsigned owner declaration is advisory only, not proof of authorization",
        "execution requires a separate, cryptographically verified permit outside this plan",
    ]
    if load_only_proof:
        limitations.append(
            "the pinned load-only proof permits no hook, host UI test, signing, "
            "installation, or device action by this tool"
        )

    return {
        "plan_version": PLAN_SCHEMA_VERSION,
        "mode": "dry_run",
        "execution_permitted": False,
        "status": "READY_FOR_INDEPENDENT_REVIEW",
        "purpose": "load_only_proof" if load_only_proof else "owned_test_package",
        "authorization": {
            "authorization_id": auth.authorization_id,
            "rights_basis": auth.rights_basis,
            "verification": "advisory_declaration_only",
            "cryptographically_verified": False,
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
            "compatibility_adapter": (
                LOAD_ONLY_PROOF_ADAPTER
                if load_only_proof
                else "not_applicable_to_owned_test_package"
            ),
            "hook": False,
            "swizzle": False,
        },
        "steps": steps,
        "required_credentials": [
            {"name": name, "provided": False, "secret": True}
            for name in (
                "signing_identity",
                "provisioning_profile",
                "registered_udid",
            )
        ],
        "review_findings": warning_codes,
        "limitations": limitations,
    }
