"""Orchestration for read-only IPA inspection."""
from __future__ import annotations

import hashlib
import os

from .bundle import (
    BundleError,
    collect_embedded_bundles,
    find_app_root,
    identity_from_info,
    read_plist,
)
from .collisions import DependencyAnalysis, analyse_dependencies
from .macho import MachOError, MachOSlice, load_macho
from .report import ArtifactInfo, Finding, IpaInspectionReport, utc_timestamp
from .safety import ArchiveLimits, ArchiveSafetyError, SafeArchive
from .signing import inspect_signing

_CHUNK = 1024 * 1024


def sha256_of_file(path: str) -> str:
    """Standalone helper retained for compatibility; the inspector does not use it."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        digest.update(_hash_handle(handle))
    return digest.hexdigest()


def _hash_handle(handle) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    while True:
        chunk = handle.read(_CHUNK)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def _descriptor_marker(handle) -> tuple[int, int, int, int]:
    stat = os.fstat(handle.fileno())
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def inspect_ipa(
    path: str,
    *,
    limits: ArchiveLimits | None = None,
    compute_sha256: bool = True,
    generated_at: str | None = None,
) -> IpaInspectionReport:
    """Inspect one IPA without extracting, modifying or trusting it.

    The archive path is opened exactly once. ZIP parsing, raw central-directory
    validation, entry reads and the artifact hash all use that same descriptor,
    so swapping the pathname mid-flight cannot mix bytes from two files.
    """
    limits = limits or ArchiveLimits()
    timestamp = generated_at or utc_timestamp()

    with open(path, "rb") as handle:
        marker = _descriptor_marker(handle)
        with SafeArchive(handle, limits) as archive:
            findings: list[Finding] = [
                Finding(code=f["code"], severity=f["severity"], detail=f["detail"], context=f)
                for f in archive.findings
            ]

            app_root = find_app_root(archive)
            info = read_plist(archive, app_root + "Info.plist")
            identity = identity_from_info(info)

            executable = app_root + (identity.executable or "")
            slices: tuple[MachOSlice, ...] = ()
            if not identity.executable:
                findings.append(
                    Finding("MISSING_EXECUTABLE_NAME", "critical", "Info.plist has no CFBundleExecutable")
                )
            elif not archive.has(executable):
                findings.append(
                    Finding(
                        "EXECUTABLE_NOT_PRESENT",
                        "critical",
                        "the declared main executable is absent from the bundle",
                        {"path": executable},
                    )
                )
            else:
                try:
                    slices = load_macho(archive, executable)
                except MachOError as exc:
                    findings.append(
                        Finding("MAIN_BINARY_UNPARSEABLE", "critical", str(exc), {"path": executable})
                    )

            bundles = collect_embedded_bundles(archive, app_root)
            nested = [
                (b.path, b.has_code_signature)
                for b in bundles["extensions"] + bundles["frameworks"]
            ]
            signing, profile_reason = inspect_signing(archive, app_root, nested)

            main_dylibs = tuple(ref for slc in slices for ref in slc.dylibs)
            dependencies = analyse_dependencies(archive, main_dylibs, bundles["frameworks"])

            findings.extend(_binary_findings(slices, identity.minimum_os))
            findings.extend(_bundle_findings(identity, bundles, signing, profile_reason))
            findings.extend(_dependency_findings(dependencies))

            size_bytes = os.fstat(handle.fileno()).st_size
            artifact_sha256 = _hash_handle(handle) if compute_sha256 else None
            if _descriptor_marker(handle) != marker:
                raise ArchiveSafetyError(
                    "ARCHIVE_CHANGED_DURING_ANALYSIS",
                    "the archive changed while it was being inspected",
                )

            artifact = ArtifactInfo(
                file_name=os.path.basename(path),
                size_bytes=size_bytes,
                entry_count=len(archive.names),
                uncompressed_bytes=getattr(archive, "uncompressed_bytes", 0),
                sha256=artifact_sha256,
            )

            return IpaInspectionReport(
                artifact=artifact,
                limits=limits.to_dict(),
                identity=identity,
                macho_slices=slices,
                bundles=bundles,
                signing=signing,
                dependencies=dependencies,
                findings=tuple(findings),
                generated_at=timestamp,
            )


def _binary_findings(slices: tuple[MachOSlice, ...], plist_min_os: str | None) -> list[Finding]:
    findings: list[Finding] = []
    if not slices:
        return findings

    encrypted = [s for s in slices if s.encrypted]
    inspected = [s for s in slices if s.cryptid is not None]
    if encrypted:
        findings.append(
            Finding(
                "MAIN_BINARY_ENCRYPTED",
                "warning",
                "the App Store encryption region is intact on at least one slice; "
                "static analysis of the protected region is limited and the image "
                "may not be usable as a build input",
                {"cryptid": [s.cryptid for s in encrypted]},
            )
        )
    elif inspected:
        findings.append(
            Finding(
                "MAIN_BINARY_DECRYPTED",
                "info",
                "Mach-O encryption flag is cleared; static metadata suggests the "
                "App Store wrapper was removed. Signature validity is not asserted",
                {"cryptid": [s.cryptid for s in inspected]},
            )
        )

    other_archs = sorted({s.arch for s in slices} - {"arm64", "arm64e"})
    if other_archs:
        findings.append(
            Finding(
                "NON_ARM64_ARCHITECTURE",
                "warning",
                "the image contains architectures other than arm64",
                {"architectures": other_archs},
            )
        )

    load_min_os = {s.min_os for s in slices if s.min_os}
    if plist_min_os and load_min_os and plist_min_os not in load_min_os:
        findings.append(
            Finding(
                "MIN_OS_MISMATCH",
                "warning",
                "Info.plist MinimumOSVersion disagrees with the Mach-O deployment target",
                {"plist": plist_min_os, "macho": sorted(load_min_os)},
            )
        )
    return findings


def _bundle_findings(
    identity,
    bundles: dict[str, list],
    signing,
    profile_reason: str | None,
) -> list[Finding]:
    findings: list[Finding] = []

    if not identity.bundle_id:
        findings.append(Finding("MISSING_BUNDLE_ID", "critical", "Info.plist has no CFBundleIdentifier"))

    if not signing.app_code_resources_present:
        findings.append(
            Finding(
                "NO_CODE_SIGNATURE",
                "warning",
                "the application bundle carries no _CodeSignature/CodeResources",
            )
        )

    for path in signing.nested_bundles_unsigned:
        findings.append(
            Finding(
                "UNSIGNED_NESTED_BUNDLE",
                "warning",
                "an embedded bundle has no signature metadata; installation may fail "
                "unless it is re-signed",
                {"path": path},
            )
        )

    if signing.provisioning_profile_present:
        findings.append(
            Finding(
                "PROVISIONING_PROFILE_PRESENT",
                "info",
                "an embedded.mobileprovision is present; this is not an unmodified App Store archive",
            )
        )
        if profile_reason:
            findings.append(
                Finding(
                    "PROVISIONING_PROFILE_UNREADABLE",
                    "warning",
                    "an embedded provisioning profile is present but could not be summarised",
                    {"reason": profile_reason},
                )
            )

    if signing.fairplay_metadata_present:
        findings.append(
            Finding("FAIRPLAY_METADATA_PRESENT", "info", "SC_Info/ is present in the bundle")
        )

    if identity.bundle_id:
        prefix = identity.bundle_id + "."
        for bundle in bundles.get("extensions", []):
            bid = bundle.bundle_id
            if bid and not bid.startswith(prefix):
                findings.append(
                    Finding(
                        "UNEXPECTED_EXTENSION_IDENTIFIER",
                        "warning",
                        "an embedded extension does not use the host bundle identifier prefix",
                        {"path": bundle.path, "bundle_id": bid, "expected_prefix": prefix},
                    )
                )

    if not bundles.get("extensions"):
        findings.append(
            Finding("NO_EMBEDDED_EXTENSIONS", "info", "the bundle embeds no .appex extensions")
        )

    return findings


def _dependency_findings(dependencies: DependencyAnalysis) -> list[Finding]:
    findings: list[Finding] = []
    refs = dependencies.unresolved_rpath_dependency_refs
    if refs:
        required = [r.name for r in refs if r.kind != "weak" and r.kind != "id"]
        weak = [r.name for r in refs if r.kind == "weak"]
    else:
        # Older report producers may not emit typed refs. Fail closed.
        required = list(dependencies.unresolved_rpath_dependencies)
        weak = []
    if required:
        findings.append(
            Finding(
                "UNRESOLVED_RPATH_DEPENDENCY",
                "critical",
                "the main binary has a required @rpath reference to a framework that "
                "is absent from the bundle; launch may fail",
                {"references": sorted(required)},
            )
        )
    if weak:
        findings.append(
            Finding(
                "WEAK_UNRESOLVED_RPATH_DEPENDENCY",
                "warning",
                "the main binary has a weak @rpath reference to a framework that is "
                "absent from the bundle; this is a review item, not a hard blocker",
                {"references": sorted(weak)},
            )
        )
    if dependencies.duplicate_framework_basenames:
        findings.append(
            Finding(
                "FRAMEWORK_NAME_COLLISION",
                "warning",
                "two or more embedded frameworks share a basename, so @rpath resolution is ambiguous",
                {"basenames": list(dependencies.duplicate_framework_basenames)},
            )
        )
    if dependencies.protected_frameworks:
        findings.append(
            Finding(
                "PROTECTED_FRAMEWORK_BASENAMES",
                "info",
                "these frameworks are linked by the host binary through @rpath; an injected "
                "framework must not reuse these basenames",
                {"basenames": list(dependencies.protected_frameworks)},
            )
        )
    return findings


def apply_limits(limits: dict) -> ArchiveLimits:
    """Rebuild limits from a serialised report, useful for replaying a run."""
    return ArchiveLimits(**limits)


__all__ = [
    "BundleError",
    "inspect_ipa",
    "sha256_of_file",
    "apply_limits",
    "ArchiveLimits",
]
