"""Static code-signing metadata inspection.

This module reads signature *metadata*. It never verifies a signature: that
needs Apple's trust chain, the signing identity and a real device, none of which
a static, offline reader has. Every report produced here therefore states
``verified: False`` with the reason, so no downstream consumer can mistake
presence for validity.
"""
from __future__ import annotations

import plistlib
from dataclasses import dataclass, field

from .safety import SafeArchive

MAX_PROVISIONING_BYTES = 1024 * 1024

_PLIST_START = b"<?xml"
_PLIST_END = b"</plist>"


class SigningError(ValueError):
    """Signing metadata exists but cannot be read."""


@dataclass(frozen=True)
class ProvisioningProfileSummary:
    name: str | None
    team_identifiers: tuple[str, ...]
    expires_at: object | None
    provisioned_device_count: int | None
    entitlement_keys: tuple[str, ...]
    platforms: tuple[str, ...]
    is_xcode_managed: bool | None

    def to_dict(self) -> dict:
        expires = self.expires_at
        if hasattr(expires, "isoformat"):
            expires = expires.isoformat()
        return {
            "name": self.name,
            "team_identifiers": list(self.team_identifiers),
            "expires_at": expires,
            "provisioned_device_count": self.provisioned_device_count,
            "entitlement_keys": list(self.entitlement_keys),
            "platforms": list(self.platforms),
            "is_xcode_managed": self.is_xcode_managed,
        }


@dataclass(frozen=True)
class SigningReport:
    app_code_resources_present: bool
    app_signature_file_count: int
    provisioning_profile_present: bool
    provisioning_profile: ProvisioningProfileSummary | None
    fairplay_metadata_present: bool
    nested_bundles_total: int
    nested_bundles_signed: int
    nested_bundles_unsigned: tuple[str, ...] = field(default_factory=tuple)
    verification: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "app_code_resources_present": self.app_code_resources_present,
            "app_signature_file_count": self.app_signature_file_count,
            "provisioning_profile_present": self.provisioning_profile_present,
            "provisioning_profile": (
                self.provisioning_profile.to_dict() if self.provisioning_profile else None
            ),
            "fairplay_metadata_present": self.fairplay_metadata_present,
            "nested_bundles_total": self.nested_bundles_total,
            "nested_bundles_signed": self.nested_bundles_signed,
            "nested_bundles_unsigned": list(self.nested_bundles_unsigned),
            "verification": dict(self.verification),
        }


def extract_embedded_plist(blob: bytes) -> dict | None:
    """Pull the XML property list out of a CMS-wrapped provisioning profile.

    A ``.mobileprovision`` is a PKCS#7 container whose payload is a plist. We
    locate the plist by its delimiters and parse it without touching the CMS
    structure, so nothing is trusted beyond what plistlib will accept.
    """
    start = blob.find(_PLIST_START)
    if start < 0:
        return None
    end = blob.find(_PLIST_END, start)
    if end < 0:
        return None
    payload = blob[start : end + len(_PLIST_END)]
    try:
        value = plistlib.loads(payload)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _summarise_profile(profile: dict) -> ProvisioningProfileSummary:
    entitlements = profile.get("Entitlements") or {}
    devices = profile.get("ProvisionedDevices")
    teams = profile.get("TeamIdentifier") or []
    platforms = profile.get("Platform") or []
    return ProvisioningProfileSummary(
        name=profile.get("Name"),
        team_identifiers=tuple(str(t) for t in teams) if isinstance(teams, list) else (str(teams),),
        expires_at=profile.get("ExpirationDate"),
        provisioned_device_count=len(devices) if isinstance(devices, list) else None,
        entitlement_keys=tuple(sorted(str(k) for k in entitlements)) if isinstance(entitlements, dict) else (),
        platforms=tuple(str(p) for p in platforms) if isinstance(platforms, list) else (str(platforms),),
        is_xcode_managed=profile.get("ProvisionsAllDevices"),
    )


def inspect_signing(
    archive: SafeArchive,
    app_root: str,
    nested_bundles: list[tuple[str, bool]],
) -> SigningReport:
    """Collect signature metadata and nested coverage for one application bundle."""
    code_signature_dir = app_root + "_CodeSignature/"
    app_code_resources = (code_signature_dir + "CodeResources") in archive.names
    signature_files = sum(1 for name in archive.names if name.startswith(code_signature_dir))

    profile_path = app_root + "embedded.mobileprovision"
    profile_summary: ProvisioningProfileSummary | None = None
    profile_present = archive.has(profile_path)
    if profile_present:
        try:
            raw = archive.read(profile_path, max_bytes=MAX_PROVISIONING_BYTES)
            parsed = extract_embedded_plist(raw)
            if parsed is not None:
                profile_summary = _summarise_profile(parsed)
        except Exception:
            profile_summary = None

    fairplay_present = any(name.startswith(app_root + "SC_Info/") for name in archive.names)

    unsigned = tuple(path for path, signed in nested_bundles if not signed)

    return SigningReport(
        app_code_resources_present=app_code_resources,
        app_signature_file_count=signature_files,
        provisioning_profile_present=profile_present,
        provisioning_profile=profile_summary,
        fairplay_metadata_present=fairplay_present,
        nested_bundles_total=len(nested_bundles),
        nested_bundles_signed=len(nested_bundles) - len(unsigned),
        nested_bundles_unsigned=unsigned,
        verification={
            "verified": False,
            "checked": "metadata presence only",
            "reason": (
                "Static, offline inspection cannot validate a code signature. "
                "Verification requires the Apple trust chain and a signing identity."
            ),
        },
    )
