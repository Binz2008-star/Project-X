"""Bounded, fail-closed Mach-O load-command append for pilot packaging.

This helper appends one ``LC_LOAD_DYLIB`` command into the zero padding that
already exists between the end of the load commands and the first file content
of a thin 64-bit Mach-O image. It performs **no relocation**: only the mach
header's ``ncmds``/``sizeofcmds`` fields and the appended command bytes change.
Every file offset, VM address, section, symbol, fixup chain and signature-blob
position remains bit-identical, so ``LC_MAIN`` entry offsets, ``LC_SYMTAB``,
``LC_DYSYMTAB``, ``LC_DYLD_INFO*``, linkedit data offsets, encryption offsets
and code-signature locations all stay valid without being rewritten.

The result is not a code signature; the output must be re-signed by an
authorized signing step before installation. If the padding cannot hold the
command, or any known file offset would collide with it, the helper raises
``MachOError`` instead of relocating anything.
"""
from __future__ import annotations

import struct

from ..ipa.macho import (
    LC_BUILD_VERSION,
    LC_CODE_SIGNATURE,
    LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64,
    LC_ID_DYLIB,
    LC_LAZY_LOAD_DYLIB,
    LC_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_RPATH,
    LC_SEGMENT_64,
    LC_UUID,
    LC_VERSION_MIN_IPHONEOS,
    MAX_LOAD_COMMAND_BYTES,
    MH_MAGIC_64,
    MachOError,
)

_HEADER = struct.Struct("<IiiIIIII")
_HEADER_SIZE = _HEADER.size

# Load commands that carry file offsets into the image. Each entry maps to the
# byte offsets (relative to the command start) of its file-offset fields.
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_SEGMENT = 0x1
LC_TWOLEVEL_HINTS = 0x16
LC_PREBOUND_DYLIB = 0x10
LC_ROUTINES = 0x11
LC_SUB_FRAMEWORK = 0x12
LC_SUB_UMBRELLA = 0x13
LC_SUB_CLIENT = 0x14
LC_SUB_LIBRARY = 0x15
LC_PREBIND_CKSUM = 0x17
LC_ROUTINES_64 = 0x1A
LC_SEGMENT_SPLIT_INFO = 0x1E
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_ENVIRONMENT = 0x27
LC_MAIN = 0x80000028
LC_SOURCE_VERSION = 0x2A
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_LINKER_OPTION = 0x2D
LC_LINKER_OPTIMIZATION_HINT = 0x2E
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_NOTE = 0x31
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_FILESET_ENTRY = 0x80000035
LC_ATOM_INFO = 0x36
LC_ID_DYLINKER = 0xE
LC_LOAD_DYLINKER = 0xF
LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5

# linkedit_data_command: dataoff(uint32) at +8, datasize at +12.
_LINKEDIT_DATA_COMMANDS = frozenset(
    {
        LC_CODE_SIGNATURE,
        LC_SEGMENT_SPLIT_INFO,
        LC_FUNCTION_STARTS,
        LC_DATA_IN_CODE,
        LC_DYLIB_CODE_SIGN_DRS,
        LC_LINKER_OPTIMIZATION_HINT,
        LC_DYLD_EXPORTS_TRIE,
        LC_DYLD_CHAINED_FIXUPS,
    }
)
_DYLD_INFO_COMMANDS = frozenset({LC_DYLD_INFO, LC_DYLD_INFO_ONLY})
_ENCRYPTION_COMMANDS = frozenset({LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64})

# Commands with no file-offset fields. Anything not listed here or in the
# offset-bearing sets is rejected so an unrecognized command can never hide a
# file offset that would collide with the appended load command.
_BENIGN_COMMANDS = frozenset(
    {
        LC_LOAD_DYLIB,
        LC_ID_DYLIB,
        LC_LOAD_DYLINKER,
        LC_ID_DYLINKER,
        LC_LAZY_LOAD_DYLIB,
        LC_LOAD_WEAK_DYLIB,
        LC_REEXPORT_DYLIB,
        LC_LOAD_UPWARD_DYLIB,
        LC_RPATH,
        LC_UUID,
        LC_VERSION_MIN_MACOSX,
        LC_VERSION_MIN_IPHONEOS,
        LC_VERSION_MIN_TVOS,
        LC_VERSION_MIN_WATCHOS,
        LC_BUILD_VERSION,
        LC_SOURCE_VERSION,
        LC_ROUTINES,
        LC_ROUTINES_64,
        LC_SUB_FRAMEWORK,
        LC_SUB_UMBRELLA,
        LC_SUB_CLIENT,
        LC_SUB_LIBRARY,
        LC_PREBIND_CKSUM,
        LC_DYLD_ENVIRONMENT,
        LC_LINKER_OPTION,
        LC_THREAD,
        LC_UNIXTHREAD,
    }
)

_ZEROFILL_SECTION_TYPES = frozenset({0x1, 0xC, 0x12})
_SECTION_TYPE_MASK = 0xFF

_MAX_DYLIB_NAME_BYTES = 1024


def _align8(value: int) -> int:
    return (value + 7) // 8 * 8


def _u32(region: bytes, offset: int) -> int:
    return struct.unpack_from("<I", region, offset)[0]


def _u64(region: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", region, offset)[0]


def _segment_offsets(command_id: int, command: bytes, size: int) -> list[int]:
    """Collect file offsets from an LC_SEGMENT / LC_SEGMENT_64 command."""
    if command_id == LC_SEGMENT_64:
        if size < 72:
            raise MachOError("LC_SEGMENT_64 command is too short")
        offsets = []
        fileoff = _u64(command, 40)
        if fileoff:
            offsets.append(fileoff)
        nsects = _u32(command, 64)
        if 72 + nsects * 80 > size:
            raise MachOError("LC_SEGMENT_64 section table exceeds command size")
        for index in range(nsects):
            base = 72 + index * 80
            flags = _u32(command, base + 64)
            section_offset = _u32(command, base + 48)
            section_reloff = _u32(command, base + 56)
            if flags & _SECTION_TYPE_MASK not in _ZEROFILL_SECTION_TYPES:
                if section_offset:
                    offsets.append(section_offset)
            if section_reloff:
                offsets.append(section_reloff)
        return offsets
    if command_id == LC_SEGMENT:
        if size < 56:
            raise MachOError("LC_SEGMENT command is too short")
        offsets = []
        fileoff = _u32(command, 32)
        if fileoff:
            offsets.append(fileoff)
        nsects = _u32(command, 48)
        if 56 + nsects * 68 > size:
            raise MachOError("LC_SEGMENT section table exceeds command size")
        for index in range(nsects):
            base = 56 + index * 68
            flags = _u32(command, base + 56)
            section_offset = _u32(command, base + 40)
            section_reloff = _u32(command, base + 48)
            if flags & _SECTION_TYPE_MASK not in _ZEROFILL_SECTION_TYPES:
                if section_offset:
                    offsets.append(section_offset)
            if section_reloff:
                offsets.append(section_reloff)
        return offsets
    raise MachOError(f"unsupported segment command {command:#x}")


def _command_file_offsets(command: int, size: int, region: bytes) -> list[int]:
    """Return every file offset referenced by one load command.

    ``region`` is the raw command bytes. Unknown or ambiguous commands raise so
    the caller can fail closed rather than guess at hidden offsets.
    """
    if command in (LC_SEGMENT, LC_SEGMENT_64):
        return _segment_offsets(command, region, size)
    if command == LC_SYMTAB:
        if size < 24:
            raise MachOError("LC_SYMTAB command is too short")
        return [v for v in (_u32(region, 8), _u32(region, 16)) if v]
    if command == LC_DYSYMTAB:
        if size < 80:
            raise MachOError("LC_DYSYMTAB command is too short")
        return [
            v
            for v in (
                _u32(region, 32),
                _u32(region, 40),
                _u32(region, 48),
                _u32(region, 56),
                _u32(region, 64),
                _u32(region, 72),
            )
            if v
        ]
    if command == LC_TWOLEVEL_HINTS:
        if size < 16:
            raise MachOError("LC_TWOLEVEL_HINTS command is too short")
        value = _u32(region, 8)
        return [value] if value else []
    if command in _LINKEDIT_DATA_COMMANDS:
        if size < 16:
            raise MachOError(f"linkedit data command {command:#x} is too short")
        value = _u32(region, 8)
        return [value] if value else []
    if command in _DYLD_INFO_COMMANDS:
        if size < 48:
            raise MachOError("LC_DYLD_INFO command is too short")
        return [
            v
            for v in (
                _u32(region, 8),
                _u32(region, 16),
                _u32(region, 24),
                _u32(region, 32),
                _u32(region, 40),
            )
            if v
        ]
    if command in _ENCRYPTION_COMMANDS:
        if size < 20:
            raise MachOError("encryption load command is too short")
        value = _u32(region, 8)
        return [value] if value else []
    if command == LC_NOTE:
        if size < 40:
            raise MachOError("LC_NOTE command is too short")
        value = _u64(region, 24)
        return [value] if value else []
    if command == LC_MAIN:
        if size < 24:
            raise MachOError("LC_MAIN command is too short")
        value = _u64(region, 8)
        return [value] if value else []
    if command == LC_FILESET_ENTRY:
        raise MachOError("fileset entry commands are not supported")
    if command in _BENIGN_COMMANDS:
        return []
    raise MachOError(f"unrecognized load command {command:#x}")


def _build_load_dylib_command(install_name: str) -> bytes:
    raw_name = install_name.encode("utf-8")
    if not raw_name or len(raw_name) > _MAX_DYLIB_NAME_BYTES:
        raise MachOError("dylib install name has an invalid length")
    command_size = _align8(24 + len(raw_name) + 1)
    command = struct.pack("<IIIIII", LC_LOAD_DYLIB, command_size, 24, 0, 0, 0)
    return (command + raw_name + b"\x00").ljust(command_size, b"\x00")


def add_load_dylib(data: bytes, install_name: str) -> bytes:
    """Return a copy of ``data`` with one ``LC_LOAD_DYLIB`` appended.

    ``data`` must be a thin, little-endian, 64-bit Mach-O image whose padding
    after the load commands can hold the new command. No bytes are relocated:
    the command is written into existing zero padding and only ``ncmds`` and
    ``sizeofcmds`` in the mach header change. Callers must check that the
    install name is not already present; this helper only appends.
    """
    if not install_name or "\x00" in install_name:
        raise MachOError("invalid dylib install name")
    if len(data) < _HEADER_SIZE:
        raise MachOError("Mach-O image is shorter than its header")

    magic, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags, reserved = (
        _HEADER.unpack_from(data)
    )
    if magic != MH_MAGIC_64:
        raise MachOError("only thin little-endian 64-bit Mach-O images are supported")
    if ncmds < 1 or ncmds > 100_000:
        raise MachOError("implausible load command count")
    if sizeofcmds < 8 or sizeofcmds > MAX_LOAD_COMMAND_BYTES:
        raise MachOError("implausible load command size")
    commands_end = _HEADER_SIZE + sizeofcmds
    if commands_end > len(data):
        raise MachOError("load commands extend beyond the available bytes")

    new_command = _build_load_dylib_command(install_name)
    new_command_size = len(new_command)
    if sizeofcmds + new_command_size > MAX_LOAD_COMMAND_BYTES:
        raise MachOError("load command region would exceed the safety ceiling")
    new_commands_end = commands_end + new_command_size
    if new_commands_end > len(data):
        raise MachOError("insufficient load-command padding in the image")

    region = data[_HEADER_SIZE:commands_end]
    offsets: list[int] = []
    cursor = 0
    for _ in range(ncmds):
        if cursor + 8 > len(region):
            raise MachOError("truncated load command header")
        command, command_size = struct.unpack_from("<II", region, cursor)
        if command_size < 8 or cursor + command_size > len(region):
            raise MachOError("load command has an invalid size")
        offsets.extend(
            _command_file_offsets(command, command_size, region[cursor : cursor + command_size])
        )
        cursor += command_size
    if cursor != len(region):
        raise MachOError("load command sizes do not fill the declared region")

    # Every file offset at or after the end of the load commands marks real
    # content. The appended command must end before the first such offset.
    content_floor = min((value for value in offsets if value >= commands_end), default=None)
    if content_floor is not None and new_commands_end > content_floor:
        raise MachOError("insufficient load-command padding before file content")

    # The bytes the new command occupies must be untouched padding.
    if any(data[commands_end:new_commands_end]):
        raise MachOError("load-command padding is not zeroed")

    header = _HEADER.pack(
        magic,
        cpu_type,
        cpu_subtype,
        file_type,
        ncmds + 1,
        sizeofcmds + new_command_size,
        flags,
        reserved,
    )
    return (
        header
        + data[_HEADER_SIZE:commands_end]
        + new_command
        + data[new_commands_end:]
    )


__all__ = ["add_load_dylib"]
