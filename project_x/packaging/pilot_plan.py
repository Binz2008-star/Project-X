"""Deterministic dry-run plan for the Instagram 456 private pilot package.

The planner reads the pinned source IPA and the unsigned Core dylib, verifies
their identities and hashes, and emits a bounded JSON plan. It is deliberately
not an executor: it never extracts the archive, edits a plist, inserts a load
command, signs code, writes an IPA, or contacts a device.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..buildmanager.preflight import (
    LOAD_ONLY_PROOF_IDENTITY,
    PRIVATE_PILOT_ADAPTER,
    PRIVATE_PILOT_APP_GROUP_PREFIX,
    PRIVATE_PILOT_BUNDLE_ID,
    PRIVATE_PILOT_DISPLAY_NAME,
    PRIVATE_PILOT_DYLIB_SHA256,
    PRIVATE_PILOT_EXTENSION_PREFIX,
    PRIVATE_PILOT_RIGHTS_BASIS,
    PRIVATE_PILOT_SOURCE_SHA256,
    PRIVATE_PILOT_URL_SCHEME,
)
from ..ipa import inspect_ipa
from ..ipa.bundle import AmbiguousAppRootError, BundleError, MalformedInfoPlistError
from ..ipa.macho import MachOError, parse_macho
from ..ipa.safety import ArchiveSafetyError

PLAN_SCHEMA_VERSION = "1.0"
DYLIB_INSTALL_NAME = "@rpath/libXinstaCore.dylib"
DYLIB_RPATH = "@executable_path/Frameworks"
ASSOCIATED_DOMAINS_ENTITLEMENT = "com.apple.developer.associated-domains"
MAX_DYLIB_BYTES = 64 * 1024 * 1024
SYSTEM_DYLIB_PREFIXES = ("/usr/lib/", "/System/Library/")


class PilotPlanError(ValueError):
    """A fail-closed planner rejection with a fixed, output-safe code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise PilotPlanError(code, detail)


def _inspect_source(ipa_path: str | Path) -> dict:
    try:
        report = inspect_ipa(str(ipa_path), compute_sha256=True)
    except (
        ArchiveSafetyError,
        AmbiguousAppRootError,
        MalformedInfoPlistError,
        BundleError,
        OSError,
    ):
        _fail("SOURCE_INSPECTION_FAILED", "source archive could not be inspected safely")

    digest = report.artifact.sha256
    if digest != PRIVATE_PILOT_SOURCE_SHA256:
        _fail("SOURCE_HASH_MISMATCH", "source archive hash is not the pinned Instagram hash")

    identity = report.identity
    source_identity = (identity.bundle_id, identity.version, identity.build_number)
    if source_identity != LOAD_ONLY_PROOF_IDENTITY:
        _fail("SOURCE_IDENTITY_MISMATCH", "source application identity is not the pinned production identity")
    if identity.minimum_os != "16.3":
        _fail("SOURCE_MIN_OS_MISMATCH", "source minimum OS is not 16.3")

    architectures = sorted({item.arch for item in report.macho_slices})
    if architectures != ["arm64"]:
        _fail("SOURCE_ARCH_MISMATCH", "source main executable is not arm64-only")
    if any(item.encrypted for item in report.macho_slices):
        _fail("SOURCE_ENCRYPTED", "source main executable is encrypted")

    extensions = report.bundles.get("extensions", [])
    if not extensions:
        _fail("SOURCE_EXTENSION_INVENTORY_MISSING", "source extension inventory is empty")
    if any(
        not isinstance(item.bundle_id, str)
        or not item.bundle_id.startswith("com.burbn.instagram.")
        for item in extensions
    ):
        _fail("SOURCE_EXTENSION_IDENTITY_MISMATCH", "source contains an unexpected extension identity")
    if not identity.url_schemes:
        _fail("SOURCE_URL_SCHEME_INVENTORY_MISSING", "source URL scheme inventory is empty")

    main_slices = report.macho_slices
    rpath_values = [path for item in main_slices for path in item.rpaths]
    if rpath_values.count(DYLIB_RPATH) > 1:
        _fail("SOURCE_RPATH_DUPLICATE", "source already declares the Core dylib rpath more than once")
    rpaths = sorted(set(rpath_values))
    core_load_command_present = any(
        ref.name == DYLIB_INSTALL_NAME
        for item in main_slices
        for ref in item.dylibs
    )
    if core_load_command_present:
        _fail("SOURCE_CORE_LOAD_COMMAND_PRESENT", "source already links the Core dylib")

    signing = report.signing
    profile = signing.provisioning_profile
    if signing.verification.get("verified", False) is not False:
        _fail("SOURCE_SIGNING_VERIFICATION_CLAIM", "static inspection claimed signature verification")
    associated_domains_present = bool(
        profile and ASSOCIATED_DOMAINS_ENTITLEMENT in profile.entitlement_keys
    )
    if associated_domains_present:
        _fail("SOURCE_ASSOCIATED_DOMAINS_PRESENT", "source declares associated domains")

    return {
        "sha256": digest,
        "bundle_id": identity.bundle_id,
        "version": identity.version,
        "build_number": identity.build_number,
        "minimum_os": identity.minimum_os,
        "architectures": architectures,
        "encrypted": False,
        "url_scheme_count": len(identity.url_schemes),
        "extension_count": len(extensions),
        "main_executable_rpaths": rpaths,
        "core_load_command_present": False,
        "signing_metadata": {
            "app_code_resources_present": signing.app_code_resources_present,
            "code_signature_entry_count": signing.code_signature_entry_count,
            "nested_bundles_total": signing.nested_bundles_total,
            "nested_bundles_with_signature_metadata": signing.nested_bundles_with_signature_metadata,
            "nested_bundles_unsigned_count": len(signing.nested_bundles_unsigned),
            "verification_claimed": signing.verification.get("verified") is True,
            "provisioning_profile_present": signing.provisioning_profile_present,
            "associated_domains_present": associated_domains_present,
            "entitlement_keys": sorted(profile.entitlement_keys) if profile else [],
            "app_groups": sorted(profile.app_groups) if profile else [],
            "keychain_access_groups": sorted(profile.keychain_access_groups) if profile else [],
        },
    }


def _inspect_dylib(dylib_path: str | Path) -> dict:
    try:
        data = Path(dylib_path).read_bytes()
    except OSError:
        _fail("DYLIB_UNREADABLE", "Core dylib could not be read")
    if not data or len(data) > MAX_DYLIB_BYTES:
        _fail("DYLIB_SIZE_INVALID", "Core dylib size is outside the accepted range")

    digest = hashlib.sha256(data).hexdigest()
    if digest != PRIVATE_PILOT_DYLIB_SHA256:
        _fail("DYLIB_HASH_MISMATCH", "Core dylib hash is not the reviewed CI artifact")
    try:
        slices = parse_macho(data)
    except MachOError:
        _fail("DYLIB_NOT_MACHO", "Core dylib is not a readable Mach-O image")
    if len(slices) != 1:
        _fail("DYLIB_SLICE_COUNT_INVALID", "Core dylib must contain exactly one Mach-O slice")
    item = slices[0]
    if item.arch != "arm64":
        _fail("DYLIB_ARCH_MISMATCH", "Core dylib is not arm64")
    if item.file_type_name != "MH_DYLIB":
        _fail("DYLIB_FILE_TYPE_MISMATCH", "Core dylib is not a Mach-O dylib")
    if item.min_os != "16.3":
        _fail("DYLIB_MIN_OS_MISMATCH", "Core dylib minimum OS is not 16.3")
    if item.has_code_signature:
        _fail("DYLIB_SIGNED", "Core dylib must be the unsigned CI artifact")
    if item.encrypted:
        _fail("DYLIB_ENCRYPTED", "Core dylib must not be encrypted")

    identifiers = [ref.name for ref in item.dylibs if ref.kind == "id"]
    if identifiers != [DYLIB_INSTALL_NAME]:
        _fail("DYLIB_ID_MISMATCH", "Core dylib install name is not pinned")
    linked = [ref.name for ref in item.dylibs if ref.kind != "id"]
    if any(
        not name.startswith(SYSTEM_DYLIB_PREFIXES)
        for name in linked
    ):
        _fail("DYLIB_EXTERNAL_DEPENDENCY", "Core dylib links a non-system dependency")

    return {
        "sha256": digest,
        "arch": item.arch,
        "file_type": item.file_type_name,
        "min_os": item.min_os,
        "install_name": DYLIB_INSTALL_NAME,
        "rpath_to_add": DYLIB_RPATH,
        "load_command_count": item.load_command_count,
        "signed": False,
        "dependencies": "system_only",
    }


def build_pilot_package_plan(ipa_path: str | Path, dylib_path: str | Path) -> dict:
    """Return a deterministic dry-run plan for the private pilot artifact.

    ``ipa_path`` must be the pinned production reference. ``dylib_path`` must be
    the unsigned arm64 iOS 16.3 Core artifact. Neither file is modified.
    """
    source = _inspect_source(ipa_path)
    dylib = _inspect_dylib(dylib_path)

    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "mode": "dry_run",
        "execution_permitted": False,
        "status": "READY_FOR_PRIVATE_HOST_REVIEW",
        "source": source,
        "dylib": dylib,
        "pilot_identity": {
            "bundle_id": PRIVATE_PILOT_BUNDLE_ID,
            "version": LOAD_ONLY_PROOF_IDENTITY[1],
            "build_number": LOAD_ONLY_PROOF_IDENTITY[2],
            "display_name": PRIVATE_PILOT_DISPLAY_NAME,
            "adapter_identifier": PRIVATE_PILOT_ADAPTER,
            "rights_basis": PRIVATE_PILOT_RIGHTS_BASIS,
            "url_scheme": PRIVATE_PILOT_URL_SCHEME,
            "app_group_prefix": PRIVATE_PILOT_APP_GROUP_PREFIX,
            "extension_prefix": PRIVATE_PILOT_EXTENSION_PREFIX,
        },
        "planned_changes": [
            {
                "code": "COPY_TO_PRIVATE_WORKDIR",
                "status": "planned",
                "detail": "Copy the pinned archive into a private work directory; never write the source.",
            },
            {
                "code": "REWRITE_BUNDLE_IDENTIFIER",
                "status": "planned",
                "detail": "Rewrite the app bundle identifier to the private pilot identifier.",
            },
            {
                "code": "SET_DISPLAY_NAME",
                "status": "planned",
                "detail": "Set CFBundleDisplayName to the pinned Xinsta value.",
            },
            {
                "code": "VERIFY_NO_ASSOCIATED_DOMAINS",
                "status": (
                    "planned"
                    if source["signing_metadata"]["associated_domains_present"]
                    else "already_absent"
                ),
                "detail": "Ensure the pilot app declares no associated-domains or app-links entitlement.",
            },
            {
                "code": "REWRITE_URL_SCHEMES",
                "status": "planned",
                "detail": "Replace all source URL schemes with the single pilot scheme.",
            },
            {
                "code": "REWRITE_EXTENSION_IDENTIFIERS",
                "status": "planned",
                "detail": "Rewrite every source extension identifier to the pilot prefix.",
            },
            {
                "code": "SET_APP_GROUP_PREFIX",
                "status": "planned",
                "detail": "Use only pilot-prefixed App Groups and no custom Keychain groups.",
            },
            {
                "code": "STAGE_DYLIB",
                "status": "planned",
                "detail": "Stage the verified unsigned Core dylib in the app Frameworks directory.",
            },
            {
                "code": "INSERT_LOAD_COMMAND",
                "status": "planned",
                "detail": "Add the pinned dylib install name to the main executable load commands.",
            },
            {
                "code": "ENSURE_DYLIB_RPATH",
                "status": (
                    "already_present"
                    if DYLIB_RPATH in source["main_executable_rpaths"]
                    else "planned"
                ),
                "detail": "Ensure @executable_path/Frameworks is present exactly once in the main executable.",
            },
        ],
        "blocked_steps": [
            {
                "code": "SIGN_DYLIB_AND_NESTED_BUNDLES",
                "reason": "signing_identity_and_pilot_profile_required",
            },
            {
                "code": "REPACKAGE_DISTINCT_PILOT_IPA",
                "reason": "signed_nested_bundles_required",
            },
            {
                "code": "RUN_READ_ONLY_ANALYZER_AND_BUILD_MANAGER",
                "reason": "signed_pilot_artifact_report_required",
            },
            {
                "code": "INSTALL_ON_PHYSICAL_DEVICE",
                "reason": "explicit_owner_approval_and_independent_review_required",
            },
        ],
        "verification": {
            "source_hash": "verified_against_actual_bytes",
            "dylib_hash": "verified_against_actual_bytes",
            "mach_o_dependencies": "system_only",
            "package_integrity": "source_archive_read_only",
            "hook": False,
            "swizzle": False,
        },
        "limitations": [
            "This plan does not modify, sign, repackage, install or launch any application.",
            "A distinct bundle identity does not prove on-device coexistence or data isolation.",
            "A Core load marker would prove only constructor execution, not hooks or feature behavior.",
            "No entitlement, signing, pairing, Developer Mode or runtime claim is made here.",
        ],
    }


def plan_json(plan: dict) -> str:
    """Serialise a plan deterministically with no timestamps or local paths."""
    return json.dumps(plan, indent=2, sort_keys=True) + "\n"
