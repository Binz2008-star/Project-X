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
        raise BundleError(f"{name!r} is not a readable property list: {exc}") from exc
    if not isinstance(value, dict):
        raise BundleError(f"{name!r} does not contain a dictionary at its root")
    return value


def find_app_root(archive: SafeArchive) -> str:
    """Return the ``Payload/<Name>.app/`` directory holding the main bundle."""
    candidates = sorted(
        {
            name[: -len("Info.plist")]
            for name in archive.names
            if name.startswith("Payload/")
            and name.count("/") == 2
            and name.endswith(".app/Info.plist")
        }
    )
    if not candidates:
        raise BundleError("no Payload/*.app/Info.plist found; this is not an application IPA")
    return candidates[0]


def identity_from_info(info: dict) -> AppIdentity:
    families = info.get("UIDeviceFamily") or []
    platforms = info.get("CFBundleSupportedPlatforms") or []
    return AppIdentity(
        bundle_id=info.get("CFBundleIdentifier"),
        name=info.get("CFBundleName"),
        display_name=info.get("CFBundleDisplayName"),
        version=info.get("CFBundleShortVersionString"),
        build_number=info.get("CFBundleVersion"),
        minimum_os=info.get("MinimumOSVersion"),
        executable=info.get("CFBundleExecutable"),
        device_families=tuple(int(x) for x in families if isinstance(x, (int, str)) and str(x).isdigit()),
        supported_platforms=tuple(str(p) for p in platforms),
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

    executable_name = info.get("CFBundleExecutable")
    if not executable_name:
        leaf = directory.rstrip("/").rsplit("/", 1)[-1]
        executable_name = leaf[: -(len(kind) + 1)] if leaf.endswith("." + kind) else leaf
    executable_path = directory + executable_name

    return EmbeddedBundle(
        path=directory,
        kind=kind,
        bundle_id=info.get("CFBundleIdentifier"),
        name=info.get("CFBundleName") or info.get("CFBundleDisplayName"),
        version=info.get("CFBundleShortVersionString"),
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
