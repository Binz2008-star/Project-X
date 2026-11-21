"""Application bundle discovery and inventory for a read-only IPA inspection."""
from __future__ import annotations

import plistlib
from dataclasses import dataclass

from .safety import SafeArchive, implied_directories

MAX_INFO_PLIST_BYTES = 4 * 1024 * 1024

_EXTENSION_SUFFIX = ".appex/"
_FRAMEWORK_SUFFIX = ".framework/"
_RESOURCE_BUNDLE_SUFFIX = ".bundle/"


class BundleError(ValueError):
    """The archive does not contain a describable application bundle."""


class AmbiguousAppRootError(BundleError):
    """More than one top-level application root would make the report ambiguous."""


class MalformedInfoPlistError(BundleError):
    """An identity value has the wrong type or an unsafe shape."""


def _optional_string(info: dict, key: str) -> str | None:
    value = info.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise MalformedInfoPlistError(f"{key} must be a non-empty string when present")
    return value


def _device_families(value: object) -> tuple[int, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise MalformedInfoPlistError("UIDeviceFamily must be a list when present")
    families: list[int] = []
    for item in value:
        if isinstance(item, bool):
            raise MalformedInfoPlistError("UIDeviceFamily entries must not be booleans")
        if isinstance(item, int):
            families.append(item)
        elif isinstance(item, str) and item.isdigit():
            families.append(int(item))
        else:
            raise MalformedInfoPlistError("UIDeviceFamily entries must be integers")
    return tuple(families)


def _supported_platforms(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise MalformedInfoPlistError("CFBundleSupportedPlatforms must be a list when present")
    platforms: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise MalformedInfoPlistError("CFBundleSupportedPlatforms entries must be strings")
        platforms.append(item)
    return tuple(platforms)


@dataclass(frozen=True)
class AppIdentity:
    bundle_id: str | None
    name: str | None
    display_name: str | None
    version: str | None
    build_number: str | None
    minimum_os: str | None
    executable: str | None
    device_families: tuple[int, ...]
    supported_platforms: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "bundle_id": self.bundle_id,
            "name": self.name,
            "display_name": self.display_name,
            "version": self.version,
            "build_number": self.build_number,
            "minimum_os": self.minimum_os,
            "executable": self.executable,
            "device_families": list(self.device_families),
            "supported_platforms": list(self.supported_platforms),
        }


@dataclass(frozen=True)
class EmbeddedBundle:
    path: str
    kind: str
    bundle_id: str | None
    name: str | None
    version: str | None
    executable: str | None
    executable_present: bool
    has_info_plist: bool
    has_code_signature: bool

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "bundle_id": self.bundle_id,
            "name": self.name,
            "version": self.version,
            "executable": self.executable,
            "executable_present": self.executable_present,
            "has_info_plist": self.has_info_plist,
            "has_code_signature": self.has_code_signature,
        }


def read_plist(archive: SafeArchive, name: str) -> dict:
    raw = archive.read(name, max_bytes=MAX_INFO_PLIST_BYTES)
    try:
        value = plistlib.loads(raw)
    except Exception as exc:  # plistlib raises several unrelated exception types
        # Parser details and archive-controlled names must never reach a report.
        raise BundleError("a property list could not be read") from exc
    if not isinstance(value, dict):
        raise BundleError("a property list does not contain a dictionary at its root")
    return value


def find_app_root(archive: SafeArchive) -> str:
    """Return the single top-level ``Payload/<Name>.app/`` directory."""
    directories = set(implied_directories(archive.names))
    directories.update(
        name
        for name in archive.names
        if name.startswith("Payload/") and name.endswith(".app/") and name.count("/") == 2
    )
    candidates = sorted(
        path
        for path in directories
        if path.startswith("Payload/") and path.endswith(".app/") and path.count("/") == 2
    )
    if not candidates:
        raise BundleError("no Payload/*.app/ directory found; this is not an application IPA")
    if len(candidates) > 1:
        # Never list the candidate names: an attacker controls them and they may
        # contain private paths or other sensitive text.
        raise AmbiguousAppRootError(
            f"more than one top-level application root was found ({len(candidates)} candidates)"
        )
    root = candidates[0]
    if not archive.has(root + "Info.plist"):
        raise BundleError("no Payload/*.app/Info.plist found; this is not an application IPA")
    return root


def identity_from_info(info: dict) -> AppIdentity:
    return AppIdentity(
        bundle_id=_optional_string(info, "CFBundleIdentifier"),
        name=_optional_string(info, "CFBundleName"),
        display_name=_optional_string(info, "CFBundleDisplayName"),
        version=_optional_string(info, "CFBundleShortVersionString"),
        build_number=_optional_string(info, "CFBundleVersion"),
        minimum_os=_optional_string(info, "MinimumOSVersion"),
        executable=_optional_string(info, "CFBundleExecutable"),
        device_families=_device_families(info.get("UIDeviceFamily")),
        supported_platforms=_supported_platforms(info.get("CFBundleSupportedPlatforms")),
    )


class BundleIndex:
    """Directory-level view of the archive, computed once."""

    def __init__(self, archive: SafeArchive) -> None:
        self._directories = implied_directories(archive.names)

    def directories(self, suffix: str) -> list[str]:
        return sorted(path for path in self._directories if path.endswith(suffix))


def describe_bundle(archive: SafeArchive, path: str, kind: str) -> EmbeddedBundle:
    """Describe one embedded ``.appex``/``.framework``/``.bundle`` directory."""
    directory = path if path.endswith("/") else path + "/"
    has_code_signature = (directory + "_CodeSignature/CodeResources") in archive.names

    info: dict = {}
    has_plist = archive.has(directory + "Info.plist")
    if has_plist:
        try:
            info = read_plist(archive, directory + "Info.plist")
        except BundleError:
            info = {}

    executable_name = _optional_string(info, "CFBundleExecutable")
    if executable_name is None:
        leaf = directory.rstrip("/").rsplit("/", 1)[-1]
        executable_name = leaf[: -(len(kind) + 1)] if leaf.endswith("." + kind) else leaf
    executable_path = directory + executable_name

    return EmbeddedBundle(
        path=directory,
        kind=kind,
        bundle_id=_optional_string(info, "CFBundleIdentifier"),
        name=_optional_string(info, "CFBundleName") or _optional_string(info, "CFBundleDisplayName"),
        version=_optional_string(info, "CFBundleShortVersionString"),
        executable=executable_path,
        executable_present=archive.has(executable_path),
        has_info_plist=has_plist,
        has_code_signature=has_code_signature,
    )


def collect_embedded_bundles(archive: SafeArchive, app_root: str) -> dict[str, list[EmbeddedBundle]]:
    """Inventory extensions, frameworks and resource bundles beneath the app."""
    index = BundleIndex(archive)
    result: dict[str, list[EmbeddedBundle]] = {
        "extensions": [],
        "frameworks": [],
        "resource_bundles": [],
    }
    for path in index.directories(_EXTENSION_SUFFIX):
        if path.startswith(app_root):
            result["extensions"].append(describe_bundle(archive, path, "appex"))
    for path in index.directories(_FRAMEWORK_SUFFIX):
        if path.startswith(app_root):
            result["frameworks"].append(describe_bundle(archive, path, "framework"))
    for path in index.directories(_RESOURCE_BUNDLE_SUFFIX):
        if path.startswith(app_root):
            result["resource_bundles"].append(describe_bundle(archive, path, "bundle"))
    return result
