"""Static code-signing metadata inspection.

This module reads signature *metadata*. It never verifies a signature: that
needs Apple's trust chain, the signing identity and a real device, none of which
a static, offline reader has. Every report produced here therefore states
``verified: False`` with the reason, so no downstream consumer can mistake
presence for validity.
"""
from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass, field
from datetime import datetime

from .safety import SafeArchive

MAX_PROVISIONING_BYTES = 1024 * 1024
MAX_GROUP_VALUES = 64
MAX_GROUP_VALUE_LENGTH = 256
_GROUP_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.*_+-]*$")

_PLIST_START = b"<?xml"
_PLIST_END = b"</plist>"


class SigningError(ValueError):
    """Signing metadata exists but cannot be read."""


def _group_values(value: object) -> tuple[str, ...]:
    """Read bounded entitlement group identifiers without echoing raw errors."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SigningError("PLIST_INVALID")
    values: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not _GROUP_VALUE_RE.match(item):
            raise SigningError("PLIST_INVALID")
        if len(item) > MAX_GROUP_VALUE_LENGTH:
            raise SigningError("PLIST_INVALID")
        values.add(item)
        if len(values) > MAX_GROUP_VALUES:
            raise SigningError("PLIST_INVALID")
    return tuple(sorted(values))


@dataclass(frozen=True)
class ProvisioningProfileSummary:
    name: str | None
    team_identifiers: tuple[str, ...]
    expires_at: str | None
    provisioned_device_count: int | None
    entitlement_keys: tuple[str, ...]
    platforms: tuple[str, ...]
    provisions_all_devices: bool | None
    app_groups: tuple[str, ...] = field(default_factory=tuple)
    keychain_access_groups: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        name = self.name if isinstance(self.name, str) and self.name else None
        expires = self.expires_at if isinstance(self.expires_at, str) and self.expires_at else None
        return {
            "name": name,
            "team_identifiers": list(self.team_identifiers),
            "expires_at": expires,
            "provisioned_device_count": self.provisioned_device_count,
            "entitlement_keys": list(self.entitlement_keys),
            "platforms": list(self.platforms),
            "provisions_all_devices": self.provisions_all_devices,
            "app_groups": list(self.app_groups),
            "keychain_access_groups": list(self.keychain_access_groups),
        }


@dataclass(frozen=True)
class SigningReport:
    app_code_resources_present: bool
    code_signature_entry_count: int
    provisioning_profile_present: bool
    provisioning_profile: ProvisioningProfileSummary | None
    fairplay_metadata_present: bool
    nested_bundles_total: int
    nested_bundles_with_signature_metadata: int
    nested_bundles_unsigned: tuple[str, ...] = field(default_factory=tuple)
    verification: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "app_code_resources_present": self.app_code_resources_present,
            "code_signature_entry_count": self.code_signature_entry_count,
            "provisioning_profile_present": self.provisioning_profile_present,
            "provisioning_profile": (
                self.provisioning_profile.to_dict() if self.provisioning_profile else None
            ),
            "fairplay_metadata_present": self.fairplay_metadata_present,
            "nested_bundles_total": self.nested_bundles_total,
            "nested_bundles_with_signature_metadata": self.nested_bundles_with_signature_metadata,
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
    all_devices = profile.get("ProvisionsAllDevices")

    name = profile.get("Name")
    if name is not None and (not isinstance(name, str) or not name):
        raise SigningError("PLIST_INVALID")

    expiration = profile.get("ExpirationDate")
    if expiration is not None:
        if not isinstance(expiration, datetime):
            raise SigningError("PLIST_INVALID")
        expiration = expiration.isoformat()

    return ProvisioningProfileSummary(
        name=name,
        team_identifiers=tuple(str(t) for t in teams) if isinstance(teams, list) else (str(teams),),
        expires_at=expiration,
        provisioned_device_count=len(devices) if isinstance(devices, list) else None,
        entitlement_keys=tuple(sorted(str(k) for k in entitlements)) if isinstance(entitlements, dict) else (),
        platforms=tuple(str(p) for p in platforms) if isinstance(platforms, list) else (str(platforms),),
        provisions_all_devices=all_devices if isinstance(all_devices, bool) else None,
        app_groups=_group_values(entitlements.get("com.apple.security.application-groups")),
        keychain_access_groups=_group_values(entitlements.get("keychain-access-groups")),
    )


def _profile_parse_reason(blob: bytes) -> str | None:
    """Return a fixed reason when a present profile cannot be summarised."""
    start = blob.find(_PLIST_START)
    if start < 0 or blob.find(_PLIST_END, start) < 0:
        return "PLIST_MISSING"
    return "PLIST_INVALID"


def inspect_signing(
    archive: SafeArchive,
    app_root: str,
    nested_bundles: list[tuple[str, bool]],
) -> tuple[SigningReport, str | None]:
    """Collect signature metadata and any fixed unreadable-profile reason."""
    code_signature_dir = app_root + "_CodeSignature/"
    app_code_resources = (code_signature_dir + "CodeResources") in archive.names
    signature_entry_count = sum(1 for name in archive.names if name.startswith(code_signature_dir))

    profile_path = app_root + "embedded.mobileprovision"
    profile_summary: ProvisioningProfileSummary | None = None
    profile_reason: str | None = None
    profile_present = archive.has(profile_path)
    if profile_present:
        raw: bytes | None = None
        try:
            raw = archive.read(profile_path, max_bytes=MAX_PROVISIONING_BYTES)
        except (KeyError, OSError):
            profile_reason = "READ_ERROR"
        except Exception:
            # ArchiveSafetyError and any unexpected parser failure are reported
            # with one fixed reason; raw exception text is never emitted.
            profile_reason = "READ_ERROR"
        if raw is not None:
            parsed = extract_embedded_plist(raw)
            if parsed is not None:
                try:
                    profile_summary = _summarise_profile(parsed)
                except SigningError:
                    # Typed-field failures use the same fixed reason as an
                    # unparseable plist; no value from the profile is echoed.
                    profile_reason = "PLIST_INVALID"
            else:
                profile_reason = _profile_parse_reason(raw)

    fairplay_present = any(name.startswith(app_root + "SC_Info/") for name in archive.names)

    unsigned = tuple(path for path, signed in nested_bundles if not signed)

    report = SigningReport(
        app_code_resources_present=app_code_resources,
        code_signature_entry_count=signature_entry_count,
        provisioning_profile_present=profile_present,
        provisioning_profile=profile_summary,
        fairplay_metadata_present=fairplay_present,
        nested_bundles_total=len(nested_bundles),
        nested_bundles_with_signature_metadata=len(nested_bundles) - len(unsigned),
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
    return report, profile_reason
