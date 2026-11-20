"""Bounded, read-only access to ZIP-based Apple archives.

Every limit in this module exists to stop analysis of an untrusted ``.ipa`` from
becoming unbounded time, memory or disk use. Nothing is ever extracted to disk:
entries are read into memory with a hard byte ceiling and discarded.

The checks are deliberately split in two:

* :class:`ArchiveSafetyError` -- the archive cannot be read safely or
  unambiguously. Analysis stops.
* ``SafeArchive.findings`` -- the archive is readable but structurally
  suspicious. Analysis continues and the observation is reported.
"""
from __future__ import annotations

import os
import re
import struct
import zipfile
from dataclasses import dataclass
from typing import Iterable


class ArchiveSafetyError(ValueError):
    """An archive failed a structural safety check, so analysis stopped."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ArchiveLimits:
    """Hard ceilings applied to any archive we open."""

    max_entries: int = 200_000
    max_total_uncompressed_bytes: int = 8 * 1024**3
    max_entry_uncompressed_bytes: int = 2 * 1024**3
    max_read_bytes: int = 64 * 1024**2
    max_compression_ratio: float = 250.0
    ratio_check_min_bytes: int = 1024**2

    def __post_init__(self) -> None:
        if self.max_entries < 1 or self.max_read_bytes < 1:
            raise ValueError("Archive limits must be positive")
        if self.max_total_uncompressed_bytes < 1 or self.max_entry_uncompressed_bytes < 1:
            raise ValueError("Archive limits must be positive")
        if self.max_compression_ratio <= 1:
            raise ValueError("Compression ratio limit must exceed 1")

    def to_dict(self) -> dict:
        return {
            "max_entries": self.max_entries,
            "max_total_uncompressed_bytes": self.max_total_uncompressed_bytes,
            "max_entry_uncompressed_bytes": self.max_entry_uncompressed_bytes,
            "max_read_bytes": self.max_read_bytes,
            "max_compression_ratio": self.max_compression_ratio,
            "ratio_check_min_bytes": self.ratio_check_min_bytes,
        }


_ALLOWED_METHODS = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflated",
}

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")

# Zip external attributes store the Unix mode in the high 16 bits.
_S_IFMT = 0o170000
_S_IFLNK = 0o120000

_EOCD_SIG = b"PK\x05\x06"
_ZIP64_LOCATOR_SIG = b"PK\x06\x07"
_ZIP64_EOCD_SIG = b"PK\x06\x06"
_CENTRAL_SIG = b"PK\x01\x02"
_MAX_ZIP_COMMENT = 64 * 1024
_ZIP64_MARKER = 0xFFFFFFFF
_ZIP64_COUNT_MARKER = 0xFFFF


def raw_central_names(path: str, max_entries: int) -> tuple[str, ...]:
    """Read entry names directly from the central directory.

    ``zipfile`` rewrites ``\\`` to ``/`` when it reads names on every platform,
    so validating its ``infolist()`` alone cannot see a Windows-style path
    traversal. The central directory is the authoritative on-disk record, so
    that is what we validate here.

    Both classic and ZIP64 end-of-central-directory records are understood;
    large IPAs routinely use ZIP64 even when they do not need it.
    """
    size = os.path.getsize(path)
    tail_length = min(size, _MAX_ZIP_COMMENT + 22)
    with open(path, "rb") as handle:
        handle.seek(size - tail_length)
        tail = handle.read(tail_length)

        eocd = tail.rfind(_EOCD_SIG)
        if eocd < 0 or eocd + 22 > len(tail):
            raise ArchiveSafetyError(
                "MALFORMED_CENTRAL_DIRECTORY", "end of central directory record not found"
            )

        (
            _sig,
            _disk,
            _cd_disk,
            _on_disk,
            count,
            cd_size,
            cd_offset,
            _comment_length,
        ) = struct.unpack_from("<4s4H2LH", tail, eocd)

        if (
            count >= _ZIP64_COUNT_MARKER
            or cd_offset >= _ZIP64_MARKER
            or cd_size >= _ZIP64_MARKER
        ):
            locator = tail.rfind(_ZIP64_LOCATOR_SIG, 0, eocd)
            if locator < 0 or locator + 20 > len(tail):
                raise ArchiveSafetyError(
                    "MALFORMED_CENTRAL_DIRECTORY", "ZIP64 locator not found where expected"
                )
            _sig, _disk, z64_offset, _disks = struct.unpack_from("<4sLQL", tail, locator)
            handle.seek(z64_offset)
            record = handle.read(56)
            if len(record) != 56 or record[:4] != _ZIP64_EOCD_SIG:
                raise ArchiveSafetyError(
                    "MALFORMED_CENTRAL_DIRECTORY", "ZIP64 end of central directory is unreadable"
                )
            (
                _sig,
                _record_size,
                _made_by,
                _needed,
                _disk,
                _cd_disk,
                _on_disk,
                count,
                cd_size,
                cd_offset,
            ) = struct.unpack_from("<4sQ2H2Q4Q", record, 0)

        if count > max_entries:
            raise ArchiveSafetyError(
                "TOO_MANY_ENTRIES", f"central directory lists {count} entries"
            )

        names: list[str] = []
        handle.seek(cd_offset)
        for index in range(count):
            header = handle.read(46)
            if len(header) != 46 or header[:4] != _CENTRAL_SIG:
                raise ArchiveSafetyError(
                    "MALFORMED_CENTRAL_DIRECTORY",
                    f"central header {index} is truncated or invalid",
                )
            flags = struct.unpack_from("<H", header, 8)[0]
            name_length, extra_length, comment_length = struct.unpack_from("<HHH", header, 28)
            raw_name = handle.read(name_length)
            if len(raw_name) != name_length:
                raise ArchiveSafetyError(
                    "MALFORMED_CENTRAL_DIRECTORY", f"entry name {index} is truncated"
                )
            encoding = "utf-8" if flags & 0x800 else "cp437"
            try:
                names.append(raw_name.decode(encoding))
            except UnicodeDecodeError:
                names.append(raw_name.decode("cp437", "replace"))
            handle.seek(extra_length + comment_length, os.SEEK_CUR)
    return tuple(names)


class SafeArchive:
    """Open a ZIP archive, validate its structure, and read entries under limits."""

    def __init__(self, path: str, limits: ArchiveLimits | None = None) -> None:
        self._limits = limits or ArchiveLimits()
        self.path = path
        self.findings: list[dict] = []
        try:
            self._zip = zipfile.ZipFile(path, "r")
        except zipfile.BadZipFile as exc:
            raise ArchiveSafetyError("NOT_A_ZIP", f"not a readable ZIP container: {exc}") from exc
        except OSError as exc:
            raise ArchiveSafetyError("UNREADABLE_ARCHIVE", str(exc)) from exc
        try:
            self._entries = {info.filename: info for info in self._zip.infolist()}
            self._names = tuple(info.filename for info in self._zip.infolist())
            # Validate what is actually on disk before trusting zipfile's view.
            self._raw_names = raw_central_names(path, self._limits.max_entries)
            for name in self._raw_names:
                self._validate_name(name)
            self._validate()
        except Exception:
            self._zip.close()
            raise

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._zip.close()

    def __enter__(self) -> "SafeArchive":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- validation --------------------------------------------------------

    def _validate(self) -> None:
        infos = list(self._zip.infolist())
        if not infos:
            raise ArchiveSafetyError("EMPTY_ARCHIVE", "archive contains no entries")
        if len(infos) > self._limits.max_entries:
            raise ArchiveSafetyError(
                "TOO_MANY_ENTRIES",
                f"{len(infos)} entries exceeds limit {self._limits.max_entries}",
            )

        seen: set[str] = set()
        duplicates: set[str] = set()
        symlinks: list[str] = []
        total_uncompressed = 0

        for info in infos:
            self._validate_name(info.filename)
            if info.filename in seen:
                duplicates.add(info.filename)
            seen.add(info.filename)

            if info.flag_bits & 0x1:
                raise ArchiveSafetyError(
                    "ENCRYPTED_ENTRY",
                    f"entry {info.filename!r} is encrypted; analysis cannot read it",
                )
            if info.compress_type not in _ALLOWED_METHODS:
                raise ArchiveSafetyError(
                    "UNSUPPORTED_COMPRESSION",
                    f"entry {info.filename!r} uses compression method {info.compress_type}",
                )

            if info.file_size > self._limits.max_entry_uncompressed_bytes:
                raise ArchiveSafetyError(
                    "ENTRY_TOO_LARGE",
                    f"entry {info.filename!r} expands to {info.file_size} bytes",
                )
            total_uncompressed += info.file_size
            if total_uncompressed > self._limits.max_total_uncompressed_bytes:
                raise ArchiveSafetyError(
                    "ARCHIVE_TOO_LARGE",
                    f"uncompressed size exceeds limit {self._limits.max_total_uncompressed_bytes}",
                )

            if (
                info.file_size >= self._limits.ratio_check_min_bytes
                and info.compress_size > 0
                and info.file_size / info.compress_size > self._limits.max_compression_ratio
            ):
                raise ArchiveSafetyError(
                    "COMPRESSION_RATIO_ABNORMAL",
                    f"entry {info.filename!r} expands {info.file_size / info.compress_size:.0f}x",
                )

            if (info.external_attr >> 16) & _S_IFMT == _S_IFLNK:
                symlinks.append(info.filename)

        self.uncompressed_bytes = total_uncompressed
        if duplicates:
            self.findings.append(
                {
                    "code": "DUPLICATE_ENTRY_NAME",
                    "severity": "warning",
                    "detail": f"{len(duplicates)} duplicate entry name(s); first occurrence is used",
                    "entries": sorted(duplicates)[:20],
                }
            )
        if symlinks:
            self.findings.append(
                {
                    "code": "SYMLINK_ENTRY",
                    "severity": "warning",
                    "detail": f"{len(symlinks)} entry/entries carry a Unix symlink mode",
                    "entries": sorted(symlinks)[:20],
                }
            )

    @staticmethod
    def _validate_name(name: str) -> None:
        if not name:
            raise ArchiveSafetyError("EMPTY_ENTRY_NAME", "archive contains an unnamed entry")
        if "\x00" in name:
            raise ArchiveSafetyError("NUL_IN_ENTRY_NAME", repr(name))
        if name.startswith("/"):
            raise ArchiveSafetyError("ABSOLUTE_ENTRY_PATH", repr(name))
        if "\\" in name:
            raise ArchiveSafetyError("BACKSLASH_ENTRY_PATH", repr(name))
        if _WINDOWS_DRIVE.match(name):
            raise ArchiveSafetyError("ABSOLUTE_ENTRY_PATH", repr(name))
        if ".." in name.split("/"):
            raise ArchiveSafetyError("PATH_TRAVERSAL", repr(name))

    # -- reading -----------------------------------------------------------

    @property
    def names(self) -> tuple[str, ...]:
        return self._names

    def has(self, name: str) -> bool:
        return name in self._entries

    def is_dir(self, name: str) -> bool:
        return name.endswith("/")

    def size_of(self, name: str) -> int:
        return self._entries[name].file_size

    def read(self, name: str, max_bytes: int | None = None) -> bytes:
        """Read one entry, refusing anything above the configured ceiling."""
        limit = self._limits.max_read_bytes
        if max_bytes is not None:
            limit = min(limit, max_bytes)
        info = self._entries.get(name)
        if info is None:
            raise KeyError(name)
        if info.file_size > limit:
            raise ArchiveSafetyError(
                "ENTRY_READ_TOO_LARGE",
                f"entry {name!r} is {info.file_size} bytes, above the {limit} byte read limit",
            )
        try:
            with self._zip.open(name) as fh:
                data = fh.read(limit + 1)
        except (zipfile.BadZipFile, EOFError, OSError) as exc:
            raise ArchiveSafetyError("CORRUPT_ENTRY", f"{name!r}: {exc}") from exc
        if len(data) > limit:
            raise ArchiveSafetyError(
                "ENTRY_READ_TOO_LARGE",
                f"entry {name!r} returned more than the {limit} byte read limit",
            )
        return data

    def read_prefix(self, name: str, length: int) -> bytes:
        """Read only the first ``length`` bytes of an entry."""
        if length < 1:
            raise ValueError("length must be positive")
        limit = min(self._limits.max_read_bytes, length)
        try:
            with self._zip.open(name) as fh:
                return fh.read(limit)
        except (zipfile.BadZipFile, EOFError, OSError) as exc:
            raise ArchiveSafetyError("CORRUPT_ENTRY", f"{name!r}: {exc}") from exc


def implied_directories(names: Iterable[str]) -> set[str]:
    """Every directory path implied by a list of entry names, each ending in '/'."""
    directories: set[str] = set()
    for name in names:
        parts = name.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]) + "/")
    return directories
