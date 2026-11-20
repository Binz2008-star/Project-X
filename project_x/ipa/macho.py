"""Minimal, bounded Mach-O reader.

Scope: describe what an app declares about itself -- architecture, linked
libraries, rpaths, encryption flag and deployment target. This is a structural
reader, not a loader and not a verifier: a successfully parsed Mach-O says
nothing about whether the code is trustworthy.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .safety import SafeArchive

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

LC_SEGMENT = 0x1
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LAZY_LOAD_DYLIB = 0x20
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_RPATH = 0x8000001C
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_VERSION_MIN_IPHONEOS = 0x25
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32

_DYLIB_COMMANDS = {
    LC_LOAD_DYLIB: "load",
    LC_LOAD_WEAK_DYLIB: "weak",
    LC_REEXPORT_DYLIB: "reexport",
    LC_LOAD_UPWARD_DYLIB: "upward",
    LC_LAZY_LOAD_DYLIB: "lazy",
    LC_ID_DYLIB: "id",
}

_CPU_TYPES = {
    7: "i386",
    12: "arm",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
}

_ARM64_SUBTYPES = {0: "arm64", 1: "arm64v8", 2: "arm64e"}

_FILE_TYPES = {
    1: "MH_OBJECT",
    2: "MH_EXECUTE",
    3: "MH_FVMLIB",
    4: "MH_CORE",
    5: "MH_PRELOAD",
    6: "MH_DYLIB",
    7: "MH_DYLINKER",
    8: "MH_BUNDLE",
    9: "MH_DYLIB_STUB",
    11: "MH_KEXT_BUNDLE",
}

# Load commands sit at the front of a slice. 32 MiB is far beyond anything
# Apple or Theos can emit, so exceeding it means the file is malformed.
MAX_LOAD_COMMAND_BYTES = 32 * 1024 * 1024

_PREFIX_ATTEMPTS = (1024 * 1024, 8 * 1024 * 1024, MAX_LOAD_COMMAND_BYTES + 4096)


class MachOError(ValueError):
    """The bytes are not a Mach-O image this reader can describe."""


@dataclass(frozen=True)
class DylibRef:
    name: str
    kind: str

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind}


@dataclass(frozen=True)
class MachOSlice:
    cpu_type: int
    cpu_subtype: int
    file_type: int
    is_64: bool
    endian: str
    flags: int
    load_command_count: int
    min_os: str | None
    sdk: str | None
    rpaths: tuple[str, ...]
    dylibs: tuple[DylibRef, ...]
    cryptid: int | None
    cryptoff: int | None
    cryptsize: int | None
    has_code_signature: bool
    uuid: str | None

    @property
    def arch(self) -> str:
        if self.cpu_type == 0x0100000C:
            return _ARM64_SUBTYPES.get(self.cpu_subtype & 0xFF, "arm64")
        return _CPU_TYPES.get(self.cpu_type, f"cpu_{self.cpu_type:#x}")

    @property
    def file_type_name(self) -> str:
        return _FILE_TYPES.get(self.file_type, f"type_{self.file_type}")

    @property
    def encrypted(self) -> bool:
        return bool(self.cryptid)

    def to_dict(self) -> dict:
        return {
            "arch": self.arch,
            "cpu_type": self.cpu_type,
            "cpu_subtype": self.cpu_subtype,
            "file_type": self.file_type_name,
            "is_64_bit": self.is_64,
            "flags": self.flags,
            "load_command_count": self.load_command_count,
            "min_os": self.min_os,
            "sdk": self.sdk,
            "rpaths": list(self.rpaths),
            "dylibs": [d.to_dict() for d in self.dylibs],
            "encryption": {
                "cryptid": self.cryptid,
                "encrypted": self.encrypted,
                "cryptoff": self.cryptoff,
                "cryptsize": self.cryptsize,
            },
            "has_code_signature_load_command": self.has_code_signature,
            "uuid": self.uuid,
        }


def _decode_version(encoded: int) -> str:
    major = (encoded >> 16) & 0xFFFF
    minor = (encoded >> 8) & 0xFF
    patch = encoded & 0xFF
    return f"{major}.{minor}.{patch}" if patch else f"{major}.{minor}"


def _read_cstring(blob: bytes, start: int, end: int) -> str:
    if start < 0 or start >= end:
        return ""
    return blob[start:end].split(b"\x00", 1)[0].decode("utf-8", "replace")


def _parse_slice(blob: bytes) -> MachOSlice:
    if len(blob) < 28:
        raise MachOError("slice shorter than a Mach-O header")

    magic_le = struct.unpack_from("<I", blob, 0)[0]
    if magic_le in (MH_MAGIC, MH_MAGIC_64):
        endian = "<"
        is_64 = magic_le == MH_MAGIC_64
    elif magic_le in (MH_CIGAM, MH_CIGAM_64):
        endian = ">"
        is_64 = magic_le == MH_CIGAM_64
    else:
        raise MachOError(f"unsupported magic {blob[:4].hex()}")

    header_size = 32 if is_64 else 28
    if len(blob) < header_size:
        raise MachOError("truncated Mach-O header")

    cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = struct.unpack_from(
        endian + "iiIIII", blob, 4
    )
    if ncmds > 100_000:
        raise MachOError(f"implausible load command count {ncmds}")
    if sizeofcmds > MAX_LOAD_COMMAND_BYTES:
        raise MachOError(f"implausible load command size {sizeofcmds}")

    region_end = header_size + sizeofcmds
    if region_end > len(blob):
        raise MachOError("load commands extend beyond the available bytes")

    rpaths: list[str] = []
    dylibs: list[DylibRef] = []
    min_os: str | None = None
    sdk: str | None = None
    cryptid: int | None = None
    cryptoff: int | None = None
    cryptsize: int | None = None
    has_code_signature = False
    uuid: str | None = None

    offset = header_size
    for _ in range(ncmds):
        if offset + 8 > region_end:
            raise MachOError("truncated load command header")
        cmd, cmdsize = struct.unpack_from(endian + "II", blob, offset)
        if cmdsize < 8 or offset + cmdsize > region_end:
            raise MachOError(f"load command {cmd:#x} has invalid size {cmdsize}")
        command_end = offset + cmdsize

        if cmd in _DYLIB_COMMANDS:
            if cmdsize >= 12:
                name_offset = struct.unpack_from(endian + "I", blob, offset + 8)[0]
                # A dylib_command has a 24-byte fixed header; the string offset
                # must point into the remaining payload, never into the header.
                if name_offset < 24 or name_offset >= cmdsize:
                    raise MachOError(f"dylib name offset {name_offset} outside load command")
                dylibs.append(
                    DylibRef(
                        _read_cstring(blob, offset + name_offset, command_end),
                        _DYLIB_COMMANDS[cmd],
                    )
                )
        elif cmd == LC_RPATH:
            if cmdsize >= 12:
                path_offset = struct.unpack_from(endian + "I", blob, offset + 8)[0]
                if path_offset < 12 or path_offset >= cmdsize:
                    raise MachOError(f"rpath offset {path_offset} outside load command")
                rpaths.append(_read_cstring(blob, offset + path_offset, command_end))
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            if cmdsize >= 20:
                cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", blob, offset + 8)
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            if cmdsize >= 16:
                version, sdk_version = struct.unpack_from(endian + "II", blob, offset + 8)
                min_os = _decode_version(version)
                sdk = _decode_version(sdk_version)
        elif cmd == LC_BUILD_VERSION:
            if cmdsize >= 24:
                _platform, minos, sdk_version = struct.unpack_from(endian + "III", blob, offset + 8)
                min_os = _decode_version(minos)
                sdk = _decode_version(sdk_version)
        elif cmd == LC_CODE_SIGNATURE:
            has_code_signature = True
        elif cmd == LC_UUID and cmdsize >= 24:
            raw = blob[offset + 8 : offset + 24]
            if len(raw) == 16:
                text = raw.hex().upper()
                uuid = "-".join(
                    [text[0:8], text[8:12], text[12:16], text[16:20], text[20:32]]
                )

        offset = command_end

    return MachOSlice(
        cpu_type=cpu_type,
        cpu_subtype=cpu_subtype,
        file_type=file_type,
        is_64=is_64,
        endian=endian,
        flags=flags,
        load_command_count=ncmds,
        min_os=min_os,
        sdk=sdk,
        rpaths=tuple(rpaths),
        dylibs=tuple(dylibs),
        cryptid=cryptid,
        cryptoff=cryptoff,
        cryptsize=cryptsize,
        has_code_signature=has_code_signature,
        uuid=uuid,
    )


def parse_macho(blob: bytes) -> tuple[MachOSlice, ...]:
    """Parse a thin or universal Mach-O image into one slice description each."""
    if len(blob) < 8:
        raise MachOError("file shorter than a Mach-O magic")

    magic = struct.unpack_from(">I", blob, 0)[0]
    if magic in (FAT_MAGIC, FAT_CIGAM):
        endian = ">" if magic == FAT_MAGIC else "<"
        count = struct.unpack_from(endian + "I", blob, 4)[0]
        if count < 1 or count > 64:
            raise MachOError(f"implausible universal binary slice count {count}")
        if 8 + count * 20 > len(blob):
            raise MachOError("truncated universal binary header")
        slices: list[MachOSlice] = []
        for index in range(count):
            _cpu, _sub, offset, size, _align = struct.unpack_from(
                endian + "iiIII", blob, 8 + index * 20
            )
            if size < 28 or offset + size > len(blob):
                raise MachOError(f"universal slice {index} exceeds available bytes")
            slices.append(_parse_slice(blob[offset : offset + size]))
        return tuple(slices)

    return (_parse_slice(blob),)


def load_macho(archive: SafeArchive, name: str) -> tuple[MachOSlice, ...]:
    """Read only as much of ``name`` as the header and load commands need."""
    last_error: Exception | None = None
    for attempt in _PREFIX_ATTEMPTS:
        prefix = archive.read_prefix(name, attempt)
        try:
            return parse_macho(prefix)
        except MachOError as exc:
            last_error = exc
            if archive.size_of(name) <= len(prefix):
                break
    raise MachOError(f"{name!r}: {last_error}")
