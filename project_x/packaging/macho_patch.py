"""Bounded, fail-closed Mach-O load-command insertion for pilot packaging.

This is a byte-level editor for thin 64-bit Mach-O images. It appends one
``LC_LOAD_DYLIB`` command and shifts every file offset that points beyond the
insertion point. File offsets that point into the load-command region are
rejected rather than guessed at. The result is not a code signature; the output
must be re-signed by an authorized signing step before installation.
"""
from __future__ import annotations

import struct

from ..ipa.macho import (
    LC_CODE_SIGNATURE,
    LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64,
    LC_LOAD_DYLIB,
    LC_SEGMENT,
    LC_SEGMENT_64,
    MH_MAGIC_64,
    MAX_LOAD_COMMAND_BYTES,
    MachOError,
)

_HEADER = struct.Struct("<IiiIIIII")
_HEADER_SIZE = _HEADER.size

LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_TWOLEVEL_HINTS = 0x10
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_LINKER_OPTIMIZATION_HINT = 0x2B
LC_DYLIB_CODE_SIGN_DRS = 0x2E
LC_NOTE = 0x31
LC_ATOM_INFO = 0x36
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_FILESET_ENTRY = 0x80000035

_LINKEDIT_COMMANDS = frozenset(
    {
        LC_CODE_SIGNATURE,
        LC_FUNCTION_STARTS,
        LC_DATA_IN_CODE,
        LC_LINKER_OPTIMIZATION_HINT,
        LC_DYLIB_CODE_SIGN_DRS,
        LC_ATOM_INFO,
        LC_DYLD_EXPORTS_TRIE,
        LC_DYLD_CHAINED_FIXUPS,
    }
)
_DYLD_INFO_COMMANDS = frozenset({LC_DYLD_INFO, LC_DYLD_INFO_ONLY})
_ENCRYPTION_COMMANDS = frozenset({LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64})

_MAX_DYLIB_NAME_BYTES = 1024


def _align8(value: int) -> int:
    return (value + 7) // 8 * 8


def _shift_u32(region: bytearray, offset: int, insertion_point: int, delta: int) -> None:
    value = struct.unpack_from("<I", region, offset)[0]
    if value == 0:
        return
    if value < insertion_point:
        raise MachOError("file offset points into the load-command region")
    struct.pack_into("<I", region, offset, value + delta)


def _shift_u64(region: bytearray, offset: int, insertion_point: int, delta: int) -> None:
    value = struct.unpack_from("<Q", region, offset)[0]
    if value == 0:
        return
    if value < insertion_point:
        raise MachOError("file offset points into the load-command region")
    struct.pack_into("<Q", region, offset, value + delta)


def _relocate_segment_64(
    region: bytearray, start: int, size: int, insertion_point: int, delta: int
) -> None:
    if size < 72:
        raise MachOError("LC_SEGMENT_64 command is too short")
    section_count = struct.unpack_from("<I", region, start + 64)[0]
    if 72 + section_count * 80 > size:
        raise MachOError("LC_SEGMENT_64 section table exceeds command size")

    fileoff = struct.unpack_from("<Q", region, start + 40)[0]
    filesize = struct.unpack_from("<Q", region, start + 48)[0]
    if fileoff < insertion_point < fileoff + filesize:
        # The header segment covers the load-command region. Keep its fileoff
        # and grow filesize so the segment mapping still includes the header.
        struct.pack_into("<Q", region, start + 48, filesize + delta)
    elif fileoff >= insertion_point:
        _shift_u64(region, start + 40, insertion_point, delta)

    for index in range(section_count):
        base = start + 72 + index * 80
        _shift_u32(region, base + 48, insertion_point, delta)
        _shift_u32(region, base + 56, insertion_point, delta)


def _relocate_segment_32(
    region: bytearray, start: int, size: int, insertion_point: int, delta: int
) -> None:
    if size < 56:
        raise MachOError("LC_SEGMENT command is too short")
    section_count = struct.unpack_from("<I", region, start + 48)[0]
    if 56 + section_count * 68 > size:
        raise MachOError("LC_SEGMENT section table exceeds command size")

    fileoff = struct.unpack_from("<I", region, start + 32)[0]
    filesize = struct.unpack_from("<I", region, start + 40)[0]
    if fileoff < insertion_point < fileoff + filesize:
        struct.pack_into("<I", region, start + 40, filesize + delta)
    elif fileoff >= insertion_point:
        _shift_u32(region, start + 32, insertion_point, delta)

    for index in range(section_count):
        base = start + 56 + index * 68
        _shift_u32(region, base + 40, insertion_point, delta)
        _shift_u32(region, base + 48, insertion_point, delta)


def _relocate_offsets(
    region: bytearray,
    start: int,
    command: int,
    size: int,
    insertion_point: int,
    delta: int,
) -> None:
    if command == LC_FILESET_ENTRY:
        raise MachOError("fileset entry commands are not supported")
    if command == LC_SEGMENT_64:
        _relocate_segment_64(region, start, size, insertion_point, delta)
    elif command == LC_SEGMENT:
        _relocate_segment_32(region, start, size, insertion_point, delta)
    elif command in _LINKEDIT_COMMANDS:
        if size < 12:
            raise MachOError(f"load command {command:#x} is too short")
        _shift_u32(region, start + 8, insertion_point, delta)
    elif command == LC_SYMTAB:
        if size < 24:
            raise MachOError("LC_SYMTAB command is too short")
        _shift_u32(region, start + 8, insertion_point, delta)
        _shift_u32(region, start + 16, insertion_point, delta)
    elif command == LC_DYSYMTAB:
        if size < 80:
            raise MachOError("LC_DYSYMTAB command is too short")
        for offset in (32, 40, 48, 56, 64, 72):
            _shift_u32(region, start + offset, insertion_point, delta)
    elif command in _DYLD_INFO_COMMANDS:
        if size < 48:
            raise MachOError("LC_DYLD_INFO command is too short")
        for offset in (8, 16, 24, 32, 40):
            _shift_u32(region, start + offset, insertion_point, delta)
    elif command == LC_TWOLEVEL_HINTS:
        if size < 16:
            raise MachOError("LC_TWOLEVEL_HINTS command is too short")
        _shift_u32(region, start + 8, insertion_point, delta)
    elif command in _ENCRYPTION_COMMANDS:
        if size < 20:
            raise MachOError("encryption load command is too short")
        _shift_u32(region, start + 8, insertion_point, delta)
    elif command == LC_NOTE:
        if size < 40:
            raise MachOError("LC_NOTE command is too short")
        _shift_u64(region, start + 24, insertion_point, delta)


def add_load_dylib(data: bytes, install_name: str) -> bytes:
    """Return a copy of ``data`` with one ``LC_LOAD_DYLIB`` appended.

    ``data`` must be a thin, little-endian, 64-bit Mach-O image. Callers must
    check that the install name is not already present; this helper only adds
    bytes and never removes or replaces an existing load command.
    """
    if not install_name or "\x00" in install_name:
        raise MachOError("invalid dylib install name")
    raw_name = install_name.encode("utf-8")
    if not raw_name or len(raw_name) > _MAX_DYLIB_NAME_BYTES:
        raise MachOError("dylib install name has an invalid length")
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
    insertion_point = _HEADER_SIZE + sizeofcmds
    if insertion_point > len(data):
        raise MachOError("load commands extend beyond the available bytes")

    new_command_size = _align8(24 + len(raw_name) + 1)
    if sizeofcmds + new_command_size > MAX_LOAD_COMMAND_BYTES:
        raise MachOError("load command region would exceed the safety ceiling")
    new_command = struct.pack(
        "<IIIIII", LC_LOAD_DYLIB, new_command_size, 24, 0, 0, 0
    ) + raw_name + b"\x00"
    new_command = new_command.ljust(new_command_size, b"\x00")

    region = bytearray(data[_HEADER_SIZE:insertion_point])
    cursor = 0
    for _ in range(ncmds):
        if cursor + 8 > len(region):
            raise MachOError("truncated load command header")
        command, command_size = struct.unpack_from("<II", region, cursor)
        if command_size < 8 or cursor + command_size > len(region):
            raise MachOError("load command has an invalid size")
        _relocate_offsets(
            region, cursor, command, command_size, insertion_point, new_command_size
        )
        cursor += command_size
    if cursor != len(region):
        raise MachOError("load command sizes do not fill the declared region")

    region.extend(new_command)
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
    return header + bytes(region) + data[insertion_point:]
