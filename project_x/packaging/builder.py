"""Fail-closed unsigned IPA executor for the private pilot package.

This module performs the deterministic file work that the dry-run planner only
describes: it copies the pinned source archive into a new file, rewrites the app
and extension identities, stages the reviewed Core dylib, adds its load command,
and re-analyzes the result. It deliberately does **not** sign code or contact a
device. The emitted IPA has invalidated signatures and must be re-signed by an
authorized signing step before installation.
"""
from __future__ import annotations

import hashlib
import plistlib
import re
import shutil
import zipfile
from pathlib import Path

from ..buildmanager.preflight import (
    LOAD_ONLY_PROOF_IDENTITY,
    PRIVATE_PILOT_APP_GROUP_PREFIX,
    PRIVATE_PILOT_BUNDLE_ID,
    PRIVATE_PILOT_DISPLAY_NAME,
    PRIVATE_PILOT_EXTENSION_PREFIX,
    PRIVATE_PILOT_URL_SCHEME,
)
from ..ipa import inspect_ipa, sha256_of_file
from ..ipa.bundle import BundleError, collect_embedded_bundles, find_app_root
from ..ipa.macho import MachOError, parse_macho
from ..ipa.safety import ArchiveSafetyError, SafeArchive
from . import pilot_plan
from .macho_patch import add_load_dylib

APP_GROUP_ENTITLEMENT = "com.apple.security.application-groups"
ASSOCIATED_DOMAINS_ENTITLEMENT = "com.apple.developer.associated-domains"
KEYCHAIN_ENTITLEMENT = "keychain-access-groups"
DYLIB_FILENAME = "libXinstaCore.dylib"
SOURCE_EXTENSION_PREFIX = LOAD_ONLY_PROOF_IDENTITY[0] + "."
SOURCE_APP_GROUP_PREFIX = "group." + LOAD_ONLY_PROOF_IDENTITY[0]

_MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
_RIGHTS_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SECRET_MARKERS = ("@", "password", "passwd", "secret", "token", "privatekey", "private_key")


class PilotBuildError(ValueError):
    """A fail-closed build rejection with a fixed, output-safe code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise PilotBuildError(code, detail)


def _validate_rights_reference(reference: str | None) -> str:
    if reference is None or not reference.strip():
        _fail(
            "RIGHTS_REFERENCE_REQUIRED",
            "a non-secret rights reference is required before changing the pinned source",
        )
    text = reference.strip()
    lowered = text.lower()
    if not _RIGHTS_REFERENCE_RE.match(text) or any(marker in lowered for marker in _SECRET_MARKERS):
        _fail("RIGHTS_REFERENCE_INVALID", "rights reference has an invalid format")
    return text


def _plist_format(raw: bytes) -> int:
    return plistlib.FMT_BINARY if raw.lstrip().startswith(b"bplist") else plistlib.FMT_XML


def _rewrite_app_info(raw: bytes) -> bytes:
    try:
        info = plistlib.loads(raw)
    except Exception:
        _fail("APP_INFO_UNREADABLE", "main Info.plist could not be parsed")
    if not isinstance(info, dict):
        _fail("APP_INFO_INVALID", "main Info.plist root is not a dictionary")

    info["CFBundleIdentifier"] = PRIVATE_PILOT_BUNDLE_ID
    info["CFBundleDisplayName"] = PRIVATE_PILOT_DISPLAY_NAME
    info["CFBundleURLTypes"] = [
        {
            "CFBundleURLName": "Xinsta Pilot Load Proof",
            "CFBundleURLSchemes": [PRIVATE_PILOT_URL_SCHEME],
        }
    ]
    return plistlib.dumps(info, fmt=_plist_format(raw))


def _rewrite_extension_info(raw: bytes) -> bytes:
    try:
        info = plistlib.loads(raw)
    except Exception:
        _fail("EXTENSION_INFO_UNREADABLE", "extension Info.plist could not be parsed")
    if not isinstance(info, dict):
        _fail("EXTENSION_INFO_INVALID", "extension Info.plist root is not a dictionary")
    bundle_id = info.get("CFBundleIdentifier")
    if not isinstance(bundle_id, str) or not bundle_id.startswith(SOURCE_EXTENSION_PREFIX):
        _fail("UNEXPECTED_EXTENSION_IDENTITY", "embedded extension has an unexpected bundle identifier")
    suffix = bundle_id[len(SOURCE_EXTENSION_PREFIX) :]
    if not suffix:
        _fail("UNEXPECTED_EXTENSION_IDENTITY", "embedded extension has an empty identity suffix")
    info["CFBundleIdentifier"] = PRIVATE_PILOT_EXTENSION_PREFIX + suffix
    return plistlib.dumps(info, fmt=_plist_format(raw))


def _rewrite_entitlements(raw: bytes) -> bytes:
    try:
        root = plistlib.loads(raw)
    except Exception:
        _fail("ENTITLEMENTS_UNREADABLE", "entitlements property list could not be parsed")
    if not isinstance(root, dict):
        _fail("ENTITLEMENTS_INVALID", "entitlements root is not a dictionary")
    entitlements = root.get("Entitlements", root)
    if not isinstance(entitlements, dict):
        _fail("ENTITLEMENTS_INVALID", "entitlements payload is not a dictionary")

    entitlements.pop(ASSOCIATED_DOMAINS_ENTITLEMENT, None)

    application_identifier = entitlements.get("application-identifier")
    if application_identifier is not None:
        if not isinstance(application_identifier, str) or "." not in application_identifier:
            _fail("UNEXPECTED_ENTITLEMENT", "application-identifier has an invalid shape")
        team_prefix = application_identifier.split(".", 1)[0]
        entitlements["application-identifier"] = f"{team_prefix}.{PRIVATE_PILOT_BUNDLE_ID}"

    groups = entitlements.get(APP_GROUP_ENTITLEMENT)
    if groups is not None:
        if not isinstance(groups, list) or not all(isinstance(item, str) for item in groups):
            _fail("UNEXPECTED_ENTITLEMENT", "application group entitlement is malformed")
        rewritten: list[str] = []
        for group in groups:
            if group.startswith(PRIVATE_PILOT_APP_GROUP_PREFIX):
                rewritten.append(group)
            elif group.startswith(SOURCE_APP_GROUP_PREFIX):
                rewritten.append(
                    PRIVATE_PILOT_APP_GROUP_PREFIX + group[len(SOURCE_APP_GROUP_PREFIX) :]
                )
            else:
                _fail("UNEXPECTED_ENTITLEMENT", "application group is outside the pilot prefix")
        entitlements[APP_GROUP_ENTITLEMENT] = rewritten

    keychain_groups = entitlements.get(KEYCHAIN_ENTITLEMENT)
    if keychain_groups:
        _fail("UNEXPECTED_ENTITLEMENT", "custom keychain access groups are not allowed")

    if root.get("Entitlements") is not None:
        root["Entitlements"] = entitlements
        payload = root
    else:
        payload = entitlements
    return plistlib.dumps(payload, fmt=_plist_format(raw))


def _is_entitlement_entry(name: str, app_root: str) -> bool:
    if not name.startswith(app_root):
        return False
    leaf = name.rsplit("/", 1)[-1]
    return leaf == "embedded.mobileprovision" or leaf.endswith((".xcent", ".entitlements"))


def _patched_executable(raw: bytes) -> bytes:
    if len(raw) > _MAX_EXECUTABLE_BYTES:
        _fail("EXECUTABLE_TOO_LARGE", "main executable exceeds the build safety ceiling")
    try:
        slices = parse_macho(raw)
    except MachOError:
        _fail("EXECUTABLE_NOT_MACHO", "main executable is not a readable Mach-O image")
    if len(slices) != 1 or slices[0].arch != "arm64":
        _fail("EXECUTABLE_SLICE_MISMATCH", "main executable must be a thin arm64 image")
    if slices[0].file_type_name != "MH_EXECUTE":
        _fail("EXECUTABLE_FILE_TYPE_MISMATCH", "main executable is not MH_EXECUTE")
    if any(ref.name == pilot_plan.DYLIB_INSTALL_NAME for ref in slices[0].dylibs):
        _fail("CORE_LOAD_COMMAND_PRESENT", "main executable already links the Core dylib")
    rpath_count = sum(1 for path in slices[0].rpaths if path == pilot_plan.DYLIB_RPATH)
    if rpath_count != 1:
        _fail("CORE_RPATH_INVALID", "main executable must declare the Core rpath exactly once")
    try:
        return add_load_dylib(raw, pilot_plan.DYLIB_INSTALL_NAME)
    except MachOError:
        _fail("LOAD_COMMAND_INSERT_FAILED", "Core load command could not be inserted safely")


def _verify_output(output: Path, source_hash: str, extension_count: int) -> dict:
    report = inspect_ipa(str(output), compute_sha256=True)
    identity = report.identity.to_dict()
    expected = {
        "bundle_id": PRIVATE_PILOT_BUNDLE_ID,
        "display_name": PRIVATE_PILOT_DISPLAY_NAME,
        "version": LOAD_ONLY_PROOF_IDENTITY[1],
        "build_number": LOAD_ONLY_PROOF_IDENTITY[2],
    }
    if any(identity.get(key) != value for key, value in expected.items()):
        _fail("OUTPUT_IDENTITY_MISMATCH", "output identity does not match the pilot declaration")
    if tuple(identity.get("url_schemes", ())) != (PRIVATE_PILOT_URL_SCHEME,):
        _fail("OUTPUT_URL_SCHEME_MISMATCH", "output URL scheme inventory is not pilot-only")

    extensions = report.bundles.get("extensions", [])
    if len(extensions) != extension_count:
        _fail("OUTPUT_EXTENSION_COUNT_MISMATCH", "output extension count changed unexpectedly")
    if any(
        not isinstance(item.bundle_id, str)
        or not item.bundle_id.startswith(PRIVATE_PILOT_EXTENSION_PREFIX)
        for item in extensions
    ):
        _fail("OUTPUT_EXTENSION_IDENTITY_MISMATCH", "output contains an unexpected extension identity")

    slices = report.macho_slices
    if len(slices) != 1:
        _fail("OUTPUT_SLICE_COUNT_MISMATCH", "output main executable slice count changed")
    if not any(ref.name == pilot_plan.DYLIB_INSTALL_NAME for ref in slices[0].dylibs):
        _fail("OUTPUT_LOAD_COMMAND_MISSING", "output does not link the Core dylib")
    if sum(1 for path in slices[0].rpaths if path == pilot_plan.DYLIB_RPATH) != 1:
        _fail("OUTPUT_RPATH_INVALID", "output Core rpath is not declared exactly once")

    with SafeArchive(str(output)) as archive:
        app_root = find_app_root(archive)
        dylib_entry = app_root + "Frameworks/" + DYLIB_FILENAME
        if not archive.has(dylib_entry):
            _fail("OUTPUT_DYLIB_MISSING", "output does not contain the staged Core dylib")

    output_hash = report.artifact.sha256
    if output_hash == source_hash:
        _fail("OUTPUT_HASH_UNCHANGED", "output hash equals the source hash")
    return {
        "status": "UNSIGNED_PACKAGE_READY_FOR_SIGNING",
        "signed": False,
        "signature_status": "invalidated_requires_resign",
        "source_sha256": source_hash,
        "output_sha256": output_hash,
        "output_name": output.name,
        "bundle_id": PRIVATE_PILOT_BUNDLE_ID,
        "display_name": PRIVATE_PILOT_DISPLAY_NAME,
        "version": LOAD_ONLY_PROOF_IDENTITY[1],
        "build_number": LOAD_ONLY_PROOF_IDENTITY[2],
        "extension_count": len(extensions),
        "url_schemes": list(identity["url_schemes"]),
    }


def _build_unsigned_pilot_ipa(
    ipa_path: str | Path,
    dylib_path: str | Path,
    output_path: str | Path,
) -> dict:
    source = Path(ipa_path)
    dylib = Path(dylib_path)
    output = Path(output_path)
    try:
        collides = output.resolve() in (source.resolve(), dylib.resolve())
    except OSError:
        _fail("OUTPUT_PATH_INVALID", "output path could not be resolved safely")
    if collides:
        _fail("OUTPUT_COLLIDES_WITH_INPUT", "output must be distinct from both inputs")

    pilot_plan.build_pilot_package_plan(ipa_path, dylib_path)
    source_hash = sha256_of_file(str(source))
    if source_hash != pilot_plan.PRIVATE_PILOT_SOURCE_SHA256:
        _fail("SOURCE_HASH_MISMATCH", "source hash changed after planning")

    with SafeArchive(str(source)) as archive:
        app_root = find_app_root(archive)
        extensions = collect_embedded_bundles(archive, app_root).get("extensions", [])
        if not extensions:
            _fail("SOURCE_EXTENSION_INVENTORY_MISSING", "source extension inventory is empty")
        source_names = tuple(archive.names)

    with zipfile.ZipFile(source) as source_zip:
        info = source_zip.read(app_root + "Info.plist")
        try:
            source_info = plistlib.loads(info)
        except Exception:
            _fail("APP_INFO_UNREADABLE", "main Info.plist could not be parsed")
        executable_name = (
            source_info.get("CFBundleExecutable") if isinstance(source_info, dict) else None
        )
        if not isinstance(executable_name, str) or not executable_name:
            _fail("EXECUTABLE_NAME_MISSING", "main Info.plist has no executable name")
        executable_path = app_root + executable_name
        executable = _patched_executable(source_zip.read(executable_path))

        extension_paths = {
            item.path + "Info.plist": _rewrite_extension_info(
                source_zip.read(item.path + "Info.plist")
            )
            for item in extensions
        }
        entitlement_paths = {
            name: _rewrite_entitlements(source_zip.read(name))
            for name in source_names
            if _is_entitlement_entry(name, app_root)
        }
        dylib_path_in_app = app_root + "Frameworks/" + DYLIB_FILENAME
        if dylib_path_in_app in source_names:
            _fail("DYLIB_STAGE_CONFLICT", "source already contains the Core dylib destination")
        dylib_bytes = dylib.read_bytes()
        if hashlib.sha256(dylib_bytes).hexdigest() != pilot_plan.PRIVATE_PILOT_DYLIB_SHA256:
            _fail("DYLIB_CHANGED_DURING_BUILD", "Core dylib changed after planning")

        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".tmp")
        try:
            with zipfile.ZipFile(temporary, "w") as output_zip:
                for entry_info in source_zip.infolist():
                    name = entry_info.filename
                    if name == app_root + "Info.plist":
                        payload = _rewrite_app_info(source_zip.read(name))
                    elif name == executable_path:
                        payload = executable
                    elif name in extension_paths:
                        payload = extension_paths[name]
                    elif name in entitlement_paths:
                        payload = entitlement_paths[name]
                    elif entry_info.is_dir():
                        output_zip.writestr(entry_info, b"")
                        continue
                    else:
                        with source_zip.open(entry_info) as reader, output_zip.open(
                            entry_info, "w"
                        ) as writer:
                            shutil.copyfileobj(reader, writer)
                        continue
                    output_zip.writestr(entry_info, payload)
                output_zip.writestr(dylib_path_in_app, dylib_bytes, zipfile.ZIP_DEFLATED)
            temporary.replace(output)
        finally:
            if temporary.exists():
                temporary.unlink()

    if sha256_of_file(str(source)) != source_hash:
        _fail("SOURCE_CHANGED_DURING_BUILD", "source hash changed during the build")
    try:
        return _verify_output(output, source_hash, len(extensions))
    except Exception:
        try:
            output.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def build_unsigned_pilot_ipa(
    ipa_path: str | Path,
    dylib_path: str | Path,
    output_path: str | Path,
    *,
    rights_reference: str | None = None,
) -> dict:
    """Build a distinct unsigned pilot IPA without touching the source file.

    The dry-run planner validates the pinned source and Core hashes first. A
    non-secret rights reference is required because the pinned source is a
    third-party proprietary application. The returned result explicitly marks
    the output unsigned; no installation claim is made.
    """
    reference = _validate_rights_reference(rights_reference)
    del reference  # validated only; never stored, logged or emitted

    try:
        return _build_unsigned_pilot_ipa(ipa_path, dylib_path, output_path)
    except PilotBuildError:
        raise
    except pilot_plan.PilotPlanError as exc:
        _fail(exc.code, exc.detail)
    except (
        ArchiveSafetyError,
        BundleError,
        KeyError,
        OSError,
        plistlib.InvalidFileException,
        zipfile.BadZipFile,
    ):
        _fail("BUILD_INPUT_INVALID", "source or output could not be processed safely")


__all__ = ["PilotBuildError", "build_unsigned_pilot_ipa"]
