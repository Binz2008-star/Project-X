"""Synthetic IPA fixture builders shared by analyzer and contract tests.

Every fixture is generated locally from a hand-built Mach-O header and a ZIP
container. No third-party IPA, credential, signing identity, device or network
access is used. Keeping these builders in one module prevents the analyzer and
report-to-plan contract tests from drifting apart.
"""
from __future__ import annotations

import plistlib
import struct
import zipfile
from pathlib import Path

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE

LC_BUILD_VERSION = 0x32
LC_RPATH = 0x8000001C
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_ID_DYLIB = 0xD
LC_ENCRYPTION_INFO_64 = 0x2C

CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007

MH_EXECUTE = 2
MH_DYLIB = 6

APP = "Payload/Demo.app/"

DEFAULT_INFO = {
    "CFBundleIdentifier": "com.example.demo",
    "CFBundleName": "Demo",
    "CFBundleDisplayName": "Demo",
    "CFBundleShortVersionString": "1.0",
    "CFBundleVersion": "42",
    "MinimumOSVersion": "16.0",
    "CFBundleExecutable": "Demo",
    "UIDeviceFamily": [1],
    "CFBundleSupportedPlatforms": ["iPhoneOS"],
}


def owned_info() -> dict:
    """Info.plist values for the fictional, owned integration-test package."""
    return {
        "CFBundleIdentifier": "demo.owned",
        "CFBundleName": "Owned Demo",
        "CFBundleDisplayName": "Owned Demo",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleVersion": "7",
        "MinimumOSVersion": "16.3",
        "CFBundleExecutable": "Demo",
        "UIDeviceFamily": [1, 2],
        "CFBundleSupportedPlatforms": ["iPhoneOS"],
    }


def _align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) // alignment * alignment


def _encode_version(text: str) -> int:
    parts = [int(p) for p in text.split(".")] + [0, 0, 0]
    return (parts[0] << 16) | (parts[1] << 8) | parts[2]


def _build_version_command(min_os: str, sdk: str = "16.3") -> bytes:
    return struct.pack(
        "<IIIIII", LC_BUILD_VERSION, 24, 2, _encode_version(min_os), _encode_version(sdk), 0
    )


def _rpath_command(path: str) -> bytes:
    raw = path.encode() + b"\x00"
    header = 12
    size = _align(header + len(raw))
    return struct.pack("<III", LC_RPATH, size, header) + raw.ljust(size - header, b"\x00")


def _dylib_command(command: int, name: str) -> bytes:
    raw = name.encode() + b"\x00"
    header = 24
    size = _align(header + len(raw))
    return (
        struct.pack("<IIIIII", command, size, header, 0, 0, 0)
        + raw.ljust(size - header, b"\x00")
    )


def _encryption_command(cryptid: int, cryptsize: int = 4096) -> bytes:
    return struct.pack("<IIIIII", LC_ENCRYPTION_INFO_64, 24, 0, cryptsize, cryptid, 0)


def build_macho(
    *,
    dylibs: tuple[tuple[str, int], ...] = (),
    rpaths: tuple[str, ...] = (),
    cryptid: int | None = None,
    min_os: str | None = "16.3",
    file_type: int = MH_EXECUTE,
    cpu_type: int = CPU_ARM64,
    cpu_subtype: int = 0,
) -> bytes:
    commands: list[bytes] = []
    if min_os:
        commands.append(_build_version_command(min_os))
    for path in rpaths:
        commands.append(_rpath_command(path))
    for name, command in dylibs:
        commands.append(_dylib_command(command, name))
    if cryptid is not None:
        commands.append(_encryption_command(cryptid))

    body = b"".join(commands)
    header = struct.pack(
        "<IiiIIIII", MH_MAGIC_64, cpu_type, cpu_subtype, file_type, len(commands), len(body), 0, 0
    )
    return header + body


def build_universal(slices: list[bytes]) -> bytes:
    count = len(slices)
    offset = _align(8 + 20 * count, 4096)
    entries: list[tuple[int, int, int, int]] = []
    payload = b""
    cursor = offset
    for blob in slices:
        cpu_type, cpu_subtype = struct.unpack_from("<ii", blob, 4)
        entries.append((cpu_type, cpu_subtype, cursor, len(blob)))
        cursor += len(blob)
        padding = _align(cursor, 4096) - cursor
        payload += blob + b"\x00" * padding
        cursor += padding

    header = struct.pack(">II", FAT_MAGIC, count)
    for cpu_type, cpu_subtype, slice_offset, size in entries:
        header += struct.pack(">iiIII", cpu_type, cpu_subtype, slice_offset, size, 12)
    return header + b"\x00" * (offset - len(header)) + payload


def base_entries(
    *,
    executable: bytes | None = None,
    info: dict | None = None,
) -> dict[str, bytes]:
    return {
        APP + "Info.plist": plistlib.dumps(info or DEFAULT_INFO, fmt=plistlib.FMT_BINARY),
        APP + "Demo": executable if executable is not None else build_macho(),
        APP + "_CodeSignature/CodeResources": b"<plist/>",
    }


def write_ipa(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path
