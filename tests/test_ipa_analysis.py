"""Tests for the read-only IPA analysis engine.

Every fixture is synthesised here: a minimal but structurally real Mach-O header
plus a ZIP container. No third-party IPA is committed, referenced or required.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import struct
import zipfile
from datetime import datetime
from pathlib import Path

import pytest

import project_x.ipa.inspector as inspector_module
import project_x.ipa.safety as safety_module
from project_x.ipa import (
    AmbiguousAppRootError,
    ArchiveLimits,
    ArchiveSafetyError,
    MalformedInfoPlistError,
    inspect_ipa,
)
from project_x.ipa.bundle import BundleError
from project_x.ipa.report import SCHEMA_VERSION
from project_x.ipa.safety import raw_central_names
import scripts.inspect_ipa as cli_module
from scripts.inspect_ipa import main as cli_main

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


# --------------------------------------------------------------------------
# Mach-O fixture builder
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# IPA fixture builder
# --------------------------------------------------------------------------


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


def finding_codes(report) -> set[str]:
    return {finding.code for finding in report.findings}


def finding(report, code: str):
    return next((f for f in report.findings if f.code == code), None)


@pytest.fixture()
def demo_ipa(tmp_path: Path) -> Path:
    return write_ipa(tmp_path / "Demo.ipa", base_entries())


# --------------------------------------------------------------------------
# Identity, hashing and structure
# --------------------------------------------------------------------------


def test_identity_hash_and_architecture(demo_ipa: Path):
    report = inspect_ipa(demo_ipa, generated_at="2026-01-01T00:00:00Z")

    assert report.identity.bundle_id == "com.example.demo"
    assert report.identity.version == "1.0"
    assert report.identity.build_number == "42"
    assert report.identity.minimum_os == "16.0"
    assert report.identity.executable == "Demo"
    assert report.identity.device_families == (1,)

    expected = hashlib.sha256(demo_ipa.read_bytes()).hexdigest()
    assert report.artifact.sha256 == expected
    assert report.artifact.file_name == "Demo.ipa"
    assert report.artifact.size_bytes == demo_ipa.stat().st_size

    assert [s.arch for s in report.macho_slices] == ["arm64"]
    assert report.macho_slices[0].file_type_name == "MH_EXECUTE"


def test_report_is_json_serialisable_with_versioned_schema(demo_ipa: Path):
    report = inspect_ipa(demo_ipa, generated_at="2026-01-01T00:00:00Z")
    payload = report.to_dict()

    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["generated_at"] == "2026-01-01T00:00:00Z"
    assert payload["analyzer"]["name"] == "project-x-ipa"
    assert payload["macho"]["architectures"] == ["arm64"]
    assert payload["interpretation"]["malware_verdict"] is None
    assert "not evidence" in payload["interpretation"]["note"]

    round_tripped = json.loads(report.to_json())
    assert round_tripped == payload


def test_sha256_can_be_skipped(demo_ipa: Path):
    report = inspect_ipa(demo_ipa, compute_sha256=False)
    assert report.artifact.sha256 is None


def test_report_contains_no_local_paths(demo_ipa: Path, tmp_path: Path):
    report = inspect_ipa(demo_ipa)
    text = report.to_json()
    assert str(tmp_path) not in text
    assert "\\\\" not in text


# --------------------------------------------------------------------------
# Mach-O level findings
# --------------------------------------------------------------------------


def test_decrypted_binary_is_reported_not_trusted(tmp_path: Path):
    entries = base_entries(executable=build_macho(cryptid=0))
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.macho_slices[0].encrypted is False
    assert "MAIN_BINARY_DECRYPTED" in finding_codes(report)
    assert "MAIN_BINARY_ENCRYPTED" not in finding_codes(report)
    assert report.signing.verification["verified"] is False


def test_encrypted_binary_is_flagged(tmp_path: Path):
    entries = base_entries(executable=build_macho(cryptid=1))
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.macho_slices[0].encrypted is True
    assert "MAIN_BINARY_ENCRYPTED" in finding_codes(report)


def test_missing_encryption_command_is_neither_claim(tmp_path: Path):
    entries = base_entries(executable=build_macho(cryptid=None))
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.macho_slices[0].cryptid is None
    assert "MAIN_BINARY_DECRYPTED" not in finding_codes(report)
    assert "MAIN_BINARY_ENCRYPTED" not in finding_codes(report)


def test_universal_binary_lists_every_architecture(tmp_path: Path):
    blob = build_universal([build_macho(cpu_type=CPU_ARM64), build_macho(cpu_type=CPU_X86_64)])
    entries = base_entries(executable=blob)
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    payload = report.to_dict()
    assert payload["macho"]["is_universal"] is True
    assert payload["macho"]["architectures"] == ["arm64", "x86_64"]
    assert "NON_ARM64_ARCHITECTURE" in finding_codes(report)


def test_minimum_os_disagreement_is_reported(tmp_path: Path):
    entries = base_entries(executable=build_macho(min_os="16.3"))
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.identity.minimum_os == "16.0"
    assert report.macho_slices[0].min_os == "16.3"
    code = finding(report, "MIN_OS_MISMATCH")
    assert code is not None
    assert code.context["plist"] == "16.0"


def test_missing_executable_is_critical(tmp_path: Path):
    entries = base_entries()
    entries.pop(APP + "Demo")
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert finding(report, "EXECUTABLE_NOT_PRESENT").severity == "critical"


# --------------------------------------------------------------------------
# Embedded content inventory
# --------------------------------------------------------------------------


def test_extension_inventory_and_signature_coverage(tmp_path: Path):
    entries = base_entries()
    entries[APP + "PlugIns/Widget.appex/Info.plist"] = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.example.demo.widget",
            "CFBundleExecutable": "Widget",
            "CFBundleName": "Widget",
        },
        fmt=plistlib.FMT_BINARY,
    )
    entries[APP + "PlugIns/Widget.appex/Widget"] = build_macho(file_type=MH_EXECUTE)
    entries[APP + "PlugIns/Widget.appex/_CodeSignature/CodeResources"] = b"<plist/>"
    entries[APP + "BCNRefreshSounds.bundle/sound.caf"] = b"\x00" * 16

    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))
    payload = report.to_dict()

    assert payload["bundles"]["counts"]["extensions"] == 1
    assert payload["bundles"]["counts"]["resource_bundles"] == 1
    extension = payload["bundles"]["extensions"][0]
    assert extension["bundle_id"] == "com.example.demo.widget"
    assert extension["has_code_signature"] is True
    assert extension["executable_present"] is True

    assert report.signing.nested_bundles_total == 1
    assert report.signing.nested_bundles_with_signature_metadata == 1
    assert "UNSIGNED_NESTED_BUNDLE" not in finding_codes(report)


def test_unsigned_nested_bundle_is_reported(tmp_path: Path):
    entries = base_entries()
    entries[APP + "PlugIns/Widget.appex/Info.plist"] = plistlib.dumps(
        {"CFBundleIdentifier": "com.example.demo.widget", "CFBundleExecutable": "Widget"},
        fmt=plistlib.FMT_BINARY,
    )
    entries[APP + "PlugIns/Widget.appex/Widget"] = build_macho()

    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.signing.nested_bundles_unsigned == (APP + "PlugIns/Widget.appex/",)
    assert finding(report, "UNSIGNED_NESTED_BUNDLE").severity == "warning"


def test_extension_with_foreign_identifier_is_reported(tmp_path: Path):
    entries = base_entries()
    entries[APP + "PlugIns/Other.appex/Info.plist"] = plistlib.dumps(
        {"CFBundleIdentifier": "com.other.thing", "CFBundleExecutable": "Other"},
        fmt=plistlib.FMT_BINARY,
    )
    entries[APP + "PlugIns/Other.appex/Other"] = build_macho()
    entries[APP + "PlugIns/Other.appex/_CodeSignature/CodeResources"] = b"<plist/>"

    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert "UNEXPECTED_EXTENSION_IDENTIFIER" in finding_codes(report)


# --------------------------------------------------------------------------
# Dependency and collision analysis
# --------------------------------------------------------------------------


def test_framework_linked_by_host_is_protected(tmp_path: Path):
    entries = base_entries(
        executable=build_macho(
            dylibs=(("@rpath/libavcodec.framework/libavcodec", LC_LOAD_DYLIB),)
        )
    )
    entries[APP + "Frameworks/libavcodec.framework/libavcodec"] = build_macho(
        dylibs=(("@rpath/libavcodec.framework/libavcodec", LC_ID_DYLIB),),
        file_type=MH_DYLIB,
        min_os=None,
    )

    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.dependencies.protected_frameworks == ("libavcodec.framework",)
    assert report.dependencies.unresolved_rpath_dependencies == ()
    assert "PROTECTED_FRAMEWORK_BASENAMES" in finding_codes(report)

    framework = report.dependencies.frameworks[0]
    assert framework.install_name == "@rpath/libavcodec.framework/libavcodec"


def test_unresolved_rpath_dependency_is_critical(tmp_path: Path):
    entries = base_entries(
        executable=build_macho(dylibs=(("@rpath/Missing.framework/Missing", LC_LOAD_DYLIB),))
    )
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.dependencies.unresolved_rpath_dependencies == ("@rpath/Missing.framework/Missing",)
    assert finding(report, "UNRESOLVED_RPATH_DEPENDENCY").severity == "critical"


def test_duplicate_framework_basenames_collide(tmp_path: Path):
    entries = base_entries()
    entries[APP + "Frameworks/Dup.framework/Dup"] = build_macho(file_type=MH_DYLIB, min_os=None)
    entries[APP + "PlugIns/Widget.appex/Frameworks/Dup.framework/Dup"] = build_macho(
        file_type=MH_DYLIB, min_os=None
    )

    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.dependencies.duplicate_framework_basenames == ("Dup.framework",)
    assert "FRAMEWORK_NAME_COLLISION" in finding_codes(report)


def test_rpath_load_command_is_captured(tmp_path: Path):
    entries = base_entries(executable=build_macho(rpaths=("@executable_path/Frameworks",)))
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))

    assert report.macho_slices[0].rpaths == ("@executable_path/Frameworks",)


# --------------------------------------------------------------------------
# Malicious / malformed archive safety
# --------------------------------------------------------------------------


def _expect_refusal(path: Path, code: str, limits: ArchiveLimits | None = None) -> None:
    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_ipa(path, limits=limits)
    assert excinfo.value.code == code


def test_path_traversal_is_refused(tmp_path: Path):
    path = write_ipa(tmp_path / "evil.ipa", {"Payload/Demo.app/Info.plist": b"x", "../escape": b"x"})
    _expect_refusal(path, "PATH_TRAVERSAL")


def test_absolute_entry_path_is_refused(tmp_path: Path):
    path = write_ipa(tmp_path / "evil.ipa", {"Payload/Demo.app/Info.plist": b"x", "/etc/passwd": b"x"})
    _expect_refusal(path, "ABSOLUTE_ENTRY_PATH")


def test_backslash_entry_path_is_refused(tmp_path: Path):
    # zipfile rewrites ``\`` to ``/`` on Windows, so the entry name is patched
    # in the finished archive: the guard must hold on every host OS.
    path = write_ipa(
        tmp_path / "evil.ipa", {"Payload/Demo.app/Info.plist": b"x", "Payload/Demo.app/x": b"x"}
    )
    path.write_bytes(path.read_bytes().replace(b"Payload/Demo.app/x", b"Payload\\Demo.app\\x"))
    _expect_refusal(path, "BACKSLASH_ENTRY_PATH")


def test_compression_bomb_is_refused(tmp_path: Path):
    path = write_ipa(
        tmp_path / "bomb.ipa",
        {"Payload/Demo.app/Info.plist": b"x", "Payload/Demo.app/bomb": b"\x00" * (4 * 1024 * 1024)},
    )
    _expect_refusal(
        path,
        "COMPRESSION_RATIO_ABNORMAL",
        ArchiveLimits(max_compression_ratio=2.0, ratio_check_min_bytes=1024),
    )


def test_entry_count_limit_is_enforced(tmp_path: Path):
    path = write_ipa(tmp_path / "many.ipa", {"a": b"1", "b": b"2", "c": b"3"})
    _expect_refusal(path, "TOO_MANY_ENTRIES", ArchiveLimits(max_entries=2))


def test_oversized_entry_is_refused(tmp_path: Path):
    path = write_ipa(tmp_path / "big.ipa", {"Payload/Demo.app/Info.plist": b"x" * 4096})
    _expect_refusal(path, "ENTRY_TOO_LARGE", ArchiveLimits(max_entry_uncompressed_bytes=1024))


def _set_zip_flag(path: Path, bit: int = 0x01) -> Path:
    """Set a general-purpose flag bit in every local and central header."""
    data = bytearray(path.read_bytes())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        index = data.find(signature)
        while index != -1:
            data[index + offset] |= bit
            index = data.find(signature, index + 1)
    path.write_bytes(bytes(data))
    return path


def test_encrypted_entries_are_refused(tmp_path: Path):
    path = write_ipa(tmp_path / "enc.ipa", {"Payload/Demo.app/Info.plist": b"x"})
    _expect_refusal(_set_zip_flag(path), "ENCRYPTED_ENTRY")


def test_non_zip_input_is_refused(tmp_path: Path):
    path = tmp_path / "notzip.ipa"
    path.write_bytes(b"this is not a zip archive")
    _expect_refusal(path, "NOT_A_ZIP")


def test_empty_archive_is_refused(tmp_path: Path):
    path = tmp_path / "empty.ipa"
    with zipfile.ZipFile(path, "w"):
        pass
    _expect_refusal(path, "EMPTY_ARCHIVE")


def test_archive_without_application_bundle_is_refused(tmp_path: Path):
    path = write_ipa(tmp_path / "lib.ipa", {"Payload/Library.dylib": build_macho()})
    with pytest.raises(BundleError):
        inspect_ipa(path)


def test_duplicate_entry_names_are_a_warning_not_a_failure(tmp_path: Path):
    path = tmp_path / "dup.ipa"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in base_entries().items():
            archive.writestr(name, data)
        archive.writestr(APP + "Assets.car", b"first")
        archive.writestr(APP + "Assets.car", b"second")

    report = inspect_ipa(path)
    assert "DUPLICATE_ENTRY_NAME" in finding_codes(report)
    duplicate = finding(report, "DUPLICATE_ENTRY_NAME")
    assert duplicate.severity == "warning"
    assert APP + "Assets.car" in duplicate.context["entries"]


def test_read_limit_blocks_oversized_info_plist(tmp_path: Path):
    # Incompressible payload so the compression-bomb guard cannot fire first.
    payload = os.urandom(5 * 1024 * 1024)
    path = write_ipa(
        tmp_path / "fatplist.ipa",
        {APP + "Info.plist": payload, APP + "Demo": build_macho()},
    )
    _expect_refusal(path, "ENTRY_READ_TOO_LARGE")


# --------------------------------------------------------------------------
# ZIP64 and parser hardening
# --------------------------------------------------------------------------


def _make_zip64(path: Path, entries: dict[str, bytes], use_markers: bool = True) -> Path:
    """Convert a normal ZIP into a ZIP64 archive without writing 4 GiB."""
    plain = write_ipa(path.with_name(path.stem + ".plain.ipa"), entries)
    data = plain.read_bytes()
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd > 0
    _disk, _cd_disk, _on_disk, count, cd_size, cd_offset, comment_length = struct.unpack_from(
        "<4H2LH", data, eocd + 4
    )
    assert comment_length == 0

    zip64_eocd = struct.pack(
        "<4sQ2H2L4Q",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        count,
        count,
        cd_size,
        cd_offset,
    )
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, eocd, 1)
    if use_markers:
        markers = struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            0xFFFF,
            0xFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
        )
    else:
        # An adjacent locator is sufficient for zipfile; the classic fields
        # can still contain small (even wrong) values.
        markers = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
    path.write_bytes(data[:eocd] + zip64_eocd + locator + markers)
    plain.unlink()
    return path


def test_zip64_archive_is_inspected(tmp_path: Path):
    path = _make_zip64(tmp_path / "Zip64.ipa", base_entries())
    report = inspect_ipa(path)

    assert report.identity.bundle_id == "com.example.demo"
    assert report.artifact.entry_count == 3
    assert [s.arch for s in report.macho_slices] == ["arm64"]


def test_zip64_locator_is_honoured_without_classic_markers(tmp_path: Path):
    path = _make_zip64(tmp_path / "Zip64NoMarkers.ipa", base_entries(), use_markers=False)
    report = inspect_ipa(path)

    assert report.identity.bundle_id == "com.example.demo"
    assert report.artifact.entry_count == 3
    assert APP + "Info.plist" in raw_central_names(str(path), 1000)


def test_fake_eocd_signature_in_comment_is_ignored(tmp_path: Path):
    path = write_ipa(tmp_path / "comment.ipa", base_entries())
    fake = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, 0, 0, 5)
    with zipfile.ZipFile(path, "a") as archive:
        archive.comment = b"noise" + fake

    # Python's own zipfile follows the last signature and sees no entries, so
    # this specific case is checked at the raw-parser layer rather than through
    # the full inspector.
    names = raw_central_names(str(path), 1000)
    assert len(names) == len(base_entries())
    assert APP + "Info.plist" in names


def test_raw_parser_refuses_out_of_range_central_directory(tmp_path: Path):
    path = write_ipa(tmp_path / "badcd.ipa", base_entries())
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd + 16, len(data) - 1)
    path.write_bytes(data)

    with pytest.raises(ArchiveSafetyError) as excinfo:
        raw_central_names(str(path), 1000)
    assert excinfo.value.code == "MALFORMED_CENTRAL_DIRECTORY"


def test_symlink_entry_is_reported(tmp_path: Path):
    path = tmp_path / "symlink.ipa"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in base_entries().items():
            archive.writestr(name, data)
        info = zipfile.ZipInfo(APP + "link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, b"Demo")

    assert "SYMLINK_ENTRY" in finding_codes(inspect_ipa(path))


def test_unsupported_compression_is_refused(tmp_path: Path):
    path = write_ipa(tmp_path / "method.ipa", base_entries())
    data = bytearray(path.read_bytes())
    central = data.find(b"PK\x01\x02")
    assert central > 0
    struct.pack_into("<H", data, central + 10, 99)
    path.write_bytes(data)

    _expect_refusal(path, "UNSUPPORTED_COMPRESSION")


def test_total_uncompressed_size_limit_is_enforced(tmp_path: Path):
    path = write_ipa(tmp_path / "total.ipa", base_entries())
    _expect_refusal(path, "ARCHIVE_TOO_LARGE", ArchiveLimits(max_total_uncompressed_bytes=128))


# --------------------------------------------------------------------------
# Mach-O edge cases
# --------------------------------------------------------------------------


def test_invalid_dylib_name_offset_marks_binary_unparseable(tmp_path: Path):
    body = struct.pack("<IIIIII", LC_LOAD_DYLIB, 24, 0, 0, 0, 0)
    header = struct.pack(
        "<IiiIIIII", MH_MAGIC_64, CPU_ARM64, 0, MH_EXECUTE, 1, len(body), 0, 0
    )
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", base_entries(executable=header + body)))

    assert "MAIN_BINARY_UNPARSEABLE" in finding_codes(report)


def test_32_bit_big_endian_macho_is_parsed(tmp_path: Path):
    blob = struct.pack(">IiiIIII", MH_MAGIC, CPU_ARM64, 0, MH_EXECUTE, 0, 0, 0)
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", base_entries(executable=blob)))

    slc = report.macho_slices[0]
    assert slc.is_64 is False
    assert slc.arch == "arm64"
    assert slc.file_type_name == "MH_EXECUTE"


def test_fat_cigam_container_is_parsed(tmp_path: Path):
    thin = build_macho()
    # FAT_CIGAM on disk is the little-endian encoding of FAT_MAGIC; our reader
    # sees it as a byte-swapped fat header and parses the fields little-endian.
    header = struct.pack("<II", FAT_MAGIC, 1) + struct.pack(
        "<iiIII", CPU_ARM64, 0, 4096, len(thin), 12
    )
    blob = header + b"\x00" * (4096 - len(header)) + thin
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", base_entries(executable=blob)))

    assert len(report.macho_slices) == 1
    assert report.macho_slices[0].arch == "arm64"


# --------------------------------------------------------------------------
# CLI never writes to the input archive
# --------------------------------------------------------------------------


def test_cli_refuses_report_path_equal_to_input(tmp_path: Path, capsys):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    before = path.read_bytes()

    assert cli_main([str(path), "--json", str(path), "--summary"]) == 2
    assert path.read_bytes() == before
    assert "OUTPUT_COLLIDES_WITH_INPUT" in capsys.readouterr().err


def test_cli_refuses_report_path_hardlinked_to_input(tmp_path: Path, capsys):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    alias = tmp_path / "alias.ipa"
    try:
        os.link(path, alias)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    before = path.read_bytes()

    assert cli_main([str(path), "--json", str(alias)]) == 2
    assert path.read_bytes() == before
    assert "OUTPUT_COLLIDES_WITH_INPUT" in capsys.readouterr().err


def test_analysis_does_not_modify_input(tmp_path: Path):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    before = (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_size)

    inspect_ipa(path)

    assert (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_size) == before


# --------------------------------------------------------------------------
# Review blockers A7-1 through A7-8
# --------------------------------------------------------------------------


def test_single_descriptor_is_used_for_parsing_and_hashing(tmp_path: Path, monkeypatch):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())

    def forbidden(*args, **kwargs):
        raise AssertionError("inspector reopened the archive path")

    monkeypatch.setattr(inspector_module, "sha256_of_file", forbidden)
    monkeypatch.setattr(inspector_module.os.path, "getsize", forbidden)

    original = safety_module.raw_central_names
    observed: list[object] = []

    def spy(source, max_entries):
        observed.append(source)
        return original(source, max_entries)

    monkeypatch.setattr(safety_module, "raw_central_names", spy)
    report = inspect_ipa(path)

    assert report.artifact.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert observed
    assert all(not isinstance(source, (str, Path)) for source in observed)


def test_descriptor_change_during_analysis_is_refused(tmp_path: Path, monkeypatch):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    original = inspector_module._descriptor_marker
    calls = {"count": 0}

    def changing_marker(handle):
        calls["count"] += 1
        if calls["count"] == 2:
            first = list(original(handle))
            first[3] += 1
            return tuple(first)
        return original(handle)

    monkeypatch.setattr(inspector_module, "_descriptor_marker", changing_marker)
    with pytest.raises(ArchiveSafetyError) as excinfo:
        inspect_ipa(path)
    assert excinfo.value.code == "ARCHIVE_CHANGED_DURING_ANALYSIS"


def test_ambiguous_top_level_application_roots_are_refused(tmp_path: Path):
    entries = base_entries()
    second = "Payload/Second.app/"
    entries[second + "Info.plist"] = plistlib.dumps(DEFAULT_INFO, fmt=plistlib.FMT_BINARY)
    entries[second + "Demo"] = build_macho()
    path = write_ipa(tmp_path / "Ambiguous.ipa", entries)

    with pytest.raises(AmbiguousAppRootError):
        inspect_ipa(path)


def test_nested_app_does_not_make_root_ambiguous(tmp_path: Path):
    entries = base_entries()
    entries[APP + "PlugIns/Widget.app/Info.plist"] = plistlib.dumps(
        DEFAULT_INFO, fmt=plistlib.FMT_BINARY
    )
    report = inspect_ipa(write_ipa(tmp_path / "Nested.ipa", entries))
    assert report.identity.bundle_id == "com.example.demo"


def test_top_level_app_root_without_plist_is_still_ambiguous(tmp_path: Path):
    entries = base_entries()
    entries["Payload/Second.app/README.txt"] = b"another application root"
    path = write_ipa(tmp_path / "Ambiguous.ipa", entries)

    with pytest.raises(AmbiguousAppRootError):
        inspect_ipa(path)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("CFBundleIdentifier", 123),
        ("CFBundleExecutable", ["Demo"]),
        ("CFBundleShortVersionString", {"major": 1}),
        ("CFBundleVersion", ""),
        ("MinimumOSVersion", True),
        ("CFBundleName", []),
        ("CFBundleDisplayName", 0),
        ("UIDeviceFamily", {"device": 1}),
        ("UIDeviceFamily", [True]),
        ("CFBundleSupportedPlatforms", 5),
        ("CFBundleSupportedPlatforms", ["iPhoneOS", 2]),
    ],
)
def test_malformed_info_plist_values_are_refused(tmp_path: Path, key, value):
    info = dict(DEFAULT_INFO)
    info[key] = value
    path = write_ipa(
        tmp_path / "Malformed.ipa",
        {APP + "Info.plist": plistlib.dumps(info, fmt=plistlib.FMT_BINARY), APP + "Demo": build_macho()},
    )
    with pytest.raises(MalformedInfoPlistError):
        inspect_ipa(path)


def test_cli_maps_malformed_info_plist_to_stable_code(tmp_path: Path, capsys):
    info = dict(DEFAULT_INFO)
    info["CFBundleIdentifier"] = 123
    path = write_ipa(
        tmp_path / "Malformed.ipa",
        {APP + "Info.plist": plistlib.dumps(info, fmt=plistlib.FMT_BINARY), APP + "Demo": build_macho()},
    )
    assert cli_main([str(path)]) == 2
    assert "INVALID_INFO_PLIST_VALUE" in capsys.readouterr().err


def test_cli_maps_ambiguous_root_to_stable_code(tmp_path: Path, capsys):
    entries = base_entries()
    second = "Payload/Second.app/"
    entries[second + "Info.plist"] = plistlib.dumps(DEFAULT_INFO, fmt=plistlib.FMT_BINARY)
    entries[second + "Demo"] = build_macho()
    path = write_ipa(tmp_path / "Ambiguous.ipa", entries)
    assert cli_main([str(path)]) == 2
    assert "AMBIGUOUS_APPLICATION_ROOT" in capsys.readouterr().err


def test_cli_maps_root_without_plist_to_ambiguous_code(tmp_path: Path, capsys):
    entries = base_entries()
    entries["Payload/Second.app/README.txt"] = b"another application root"
    path = write_ipa(tmp_path / "Ambiguous.ipa", entries)
    assert cli_main([str(path)]) == 2
    assert "AMBIGUOUS_APPLICATION_ROOT" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("CFBundleExecutable", 123),
        ("CFBundleIdentifier", 456),
        ("CFBundleName", ["Widget"]),
        ("CFBundleShortVersionString", {"major": 1}),
    ],
)
def test_malformed_nested_info_plist_values_are_refused(tmp_path: Path, key, value):
    entries = base_entries()
    nested = APP + "PlugIns/Widget.appex/"
    nested_info = {
        "CFBundleIdentifier": "com.example.demo.widget",
        "CFBundleExecutable": "Widget",
        key: value,
    }
    entries[nested + "Info.plist"] = plistlib.dumps(nested_info, fmt=plistlib.FMT_BINARY)
    entries[nested + "Widget"] = build_macho()
    path = write_ipa(tmp_path / "NestedMalformed.ipa", entries)

    with pytest.raises(MalformedInfoPlistError):
        inspect_ipa(path)


def test_cli_maps_malformed_nested_plist_to_stable_code(tmp_path: Path, capsys):
    entries = base_entries()
    nested = APP + "PlugIns/Widget.appex/"
    entries[nested + "Info.plist"] = plistlib.dumps(
        {"CFBundleIdentifier": 123, "CFBundleExecutable": "Widget"}, fmt=plistlib.FMT_BINARY
    )
    entries[nested + "Widget"] = build_macho()
    path = write_ipa(tmp_path / "NestedMalformed.ipa", entries)

    assert cli_main([str(path)]) == 2
    assert "INVALID_INFO_PLIST_VALUE" in capsys.readouterr().err


def test_unreadable_provisioning_profile_is_reported(tmp_path: Path):
    entries = base_entries()
    entries[APP + "embedded.mobileprovision"] = b"not-a-profile"
    report = inspect_ipa(write_ipa(tmp_path / "Profile.ipa", entries))

    profile_finding = finding(report, "PROVISIONING_PROFILE_UNREADABLE")
    assert profile_finding is not None
    assert profile_finding.severity == "warning"
    assert profile_finding.context["reason"] in {"PLIST_MISSING", "PLIST_INVALID"}
    assert report.signing.provisioning_profile is None


def test_valid_provisioning_profile_summary_uses_accurate_field_names(tmp_path: Path):
    plist = plistlib.dumps(
        {
            "Name": "Demo Profile",
            "TeamIdentifier": ["TEAM123"],
            "ExpirationDate": datetime(2026, 12, 31, 23, 59, 59),
            "ProvisionsAllDevices": True,
        },
        fmt=plistlib.FMT_XML,
    )
    entries = base_entries()
    entries[APP + "embedded.mobileprovision"] = b"CMS-header" + plist + b"CMS-footer"
    report = inspect_ipa(write_ipa(tmp_path / "Profile.ipa", entries))

    assert "PROVISIONING_PROFILE_UNREADABLE" not in finding_codes(report)
    assert report.signing.provisioning_profile is not None
    assert report.signing.provisioning_profile.provisions_all_devices is True
    payload = report.to_dict()["signing"]["provisioning_profile"]
    assert "is_xcode_managed" not in payload
    assert payload["name"] == "Demo Profile"
    assert payload["expires_at"] == "2026-12-31T23:59:59"
    assert payload["provisions_all_devices"] is True
    signing = report.to_dict()["signing"]
    assert "app_signature_file_count" not in signing
    assert "nested_bundles_signed" not in signing
    assert signing["code_signature_entry_count"] == 1


@pytest.mark.parametrize(
    ("field", "value", "case_id"),
    [
        pytest.param("Name", 123, "name-int", id="name-int"),
        pytest.param("Name", {"unexpected": "value"}, "name-dict", id="name-dict"),
        pytest.param("Name", b"bytes", "name-bytes", id="name-bytes"),
        pytest.param("ExpirationDate", b"\x01\x02", "expires-bytes", id="expires-bytes"),
        pytest.param("ExpirationDate", {"unexpected": "value"}, "expires-dict", id="expires-dict"),
        pytest.param("ExpirationDate", [2026, 1, 1], "expires-list", id="expires-list"),
    ],
)
def test_malformed_profile_summary_values_are_refused_without_breaking_json(
    tmp_path: Path, capsys, field: str, value, case_id: str
):
    plist = plistlib.dumps(
        {"TeamIdentifier": ["TEAM123"], field: value},
        fmt=plistlib.FMT_XML,
    )
    entries = base_entries()
    entries[APP + "embedded.mobileprovision"] = b"CMS-header" + plist + b"CMS-footer"
    path = write_ipa(tmp_path / f"MalformedProfile-{case_id}.ipa", entries)

    report = inspect_ipa(path)

    profile_finding = finding(report, "PROVISIONING_PROFILE_UNREADABLE")
    assert profile_finding is not None
    assert profile_finding.context["reason"] == "PLIST_INVALID"
    assert report.signing.provisioning_profile is None
    assert report.to_dict()["signing"]["provisioning_profile"] is None
    assert json.loads(report.to_json())["signing"]["provisioning_profile"] is None

    output = tmp_path / f"MalformedProfile-{case_id}.json"
    assert cli_main([str(path), "--json", str(output), "--summary"]) == 0
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    assert json.loads(output.read_text(encoding="utf-8"))["signing"]["provisioning_profile"] is None


def test_cli_refusals_do_not_echo_private_paths(tmp_path: Path, capsys):
    private = tmp_path / "private-family-photos"
    private.mkdir()
    missing = private / "missing.ipa"

    capsys.readouterr()
    assert cli_main([str(missing)]) == 2
    captured = capsys.readouterr()
    assert "FILE_NOT_FOUND" in captured.err
    assert "private-family-photos" not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err

    capsys.readouterr()
    assert cli_main([str(private)]) == 2
    captured = capsys.readouterr()
    assert "FILE_NOT_FOUND" in captured.err
    assert "private-family-photos" not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err

    invalid_invocations = [
        [str(missing), "--max-entries", str(private / "not-an-int")],
        [str(missing), "--max-total-bytes", str(private / "not-an-int")],
        [str(missing), "--private-family-photos", str(private / "value")],
        [str(missing), "--max-entries", "0"],
        [str(missing), "--max-entries", "-1"],
        [str(missing), "--max-total-bytes", "0"],
        [str(missing), "--max-total-bytes", "-1"],
    ]
    for arguments in invalid_invocations:
        capsys.readouterr()
        assert cli_main(arguments) == 2
        captured = capsys.readouterr()
        assert "INVALID_ARGUMENTS" in captured.err
        assert "private-family-photos" not in captured.out + captured.err
        assert "Traceback" not in captured.out + captured.err


def test_weak_unresolved_rpath_dependency_is_a_warning_with_kind(tmp_path: Path):
    entries = base_entries(
        executable=build_macho(
            dylibs=(("@rpath/Missing.framework/Missing", LC_LOAD_WEAK_DYLIB),)
        )
    )
    report = inspect_ipa(write_ipa(tmp_path / "Weak.ipa", entries))
    refs = report.dependencies.unresolved_rpath_dependency_refs

    assert len(refs) == 1
    assert refs[0].name == "@rpath/Missing.framework/Missing"
    assert refs[0].kind == "weak"
    assert finding(report, "WEAK_UNRESOLVED_RPATH_DEPENDENCY").severity == "warning"
    assert finding(report, "UNRESOLVED_RPATH_DEPENDENCY") is None


def test_required_and_weak_unresolved_rpath_dependencies_are_distinct(tmp_path: Path):
    entries = base_entries(
        executable=build_macho(
            dylibs=(
                ("@rpath/Required.framework/Required", LC_LOAD_DYLIB),
                ("@rpath/Optional.framework/Optional", LC_LOAD_WEAK_DYLIB),
            )
        )
    )
    report = inspect_ipa(write_ipa(tmp_path / "Mixed.ipa", entries))

    assert {ref.kind for ref in report.dependencies.unresolved_rpath_dependency_refs} == {
        "load",
        "weak",
    }
    assert finding(report, "UNRESOLVED_RPATH_DEPENDENCY").severity == "critical"
    assert finding(report, "WEAK_UNRESOLVED_RPATH_DEPENDENCY").severity == "warning"


@pytest.mark.parametrize(("subtype", "arch"), [(0, "arm64"), (1, "arm64"), (2, "arm64e")])
def test_arm64_subtypes_are_normalised(tmp_path: Path, subtype, arch):
    entries = base_entries(executable=build_macho(cpu_subtype=subtype))
    report = inspect_ipa(write_ipa(tmp_path / "Demo.ipa", entries))
    assert [slc.arch for slc in report.macho_slices] == [arch]


def test_cli_does_not_follow_output_symlink(tmp_path: Path, capsys):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("DO-NOT-OVERWRITE", encoding="utf-8")
    output = tmp_path / "report.json"
    try:
        output.symlink_to(sentinel)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this filesystem")

    assert cli_main([str(path), "--json", str(output)]) == 2
    captured = capsys.readouterr()
    assert "OUTPUT_WRITE_FAILED" in captured.err
    assert sentinel.read_text(encoding="utf-8") == "DO-NOT-OVERWRITE"
    assert output.is_symlink()
    assert not list(tmp_path.glob(".inspect-ipa-*"))


def test_cli_does_not_overwrite_an_existing_report(tmp_path: Path, capsys):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    output = tmp_path / "report.json"
    output.write_text("EXISTING-REPORT", encoding="utf-8")

    assert cli_main([str(path), "--json", str(output)]) == 2
    captured = capsys.readouterr()
    assert "OUTPUT_WRITE_FAILED" in captured.err
    assert output.read_text(encoding="utf-8") == "EXISTING-REPORT"
    assert not list(tmp_path.glob(".inspect-ipa-*"))


def test_cli_refuses_input_renamed_onto_output_during_publication(
    tmp_path: Path, monkeypatch, capsys
):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    before = path.read_bytes()
    output = tmp_path / "report.json"
    real_link = os.link
    calls = {"count": 0}

    def racing_link(source, target):
        calls["count"] += 1
        os.rename(path, target)
        return real_link(source, target)

    monkeypatch.setattr(cli_module.os, "link", racing_link)

    assert cli_main([str(path), "--json", str(output)]) == 2
    assert calls["count"] == 1
    assert "OUTPUT_COLLIDES_WITH_INPUT" in capsys.readouterr().err
    assert output.read_bytes() == before
    assert not path.exists()
    assert not list(tmp_path.glob(".inspect-ipa-*"))


def test_cli_never_unlinks_the_output_target(tmp_path: Path, monkeypatch, capsys):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    output = tmp_path / "report.json"
    real_unlink = cli_module.Path.unlink
    unlinked: list[str] = []

    def tracking_unlink(self, *args, **kwargs):
        unlinked.append(str(self))
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(cli_module.Path, "unlink", tracking_unlink)

    assert cli_main([str(path), "--json", str(output)]) == 0
    capsys.readouterr()
    assert output.is_file()
    assert not any(Path(item) == output for item in unlinked)


def test_cli_preserves_input_when_temporary_path_is_replaced_during_publication(
    tmp_path: Path, monkeypatch, capsys
):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    before = path.read_bytes()
    output = tmp_path / "report.json"
    output.write_text("EXISTING-REPORT", encoding="utf-8")
    real_link = cli_module.os.link

    def swapping_link(source, target):
        Path(source).unlink()
        os.replace(path, source)
        return real_link(source, target)

    monkeypatch.setattr(cli_module.os, "link", swapping_link)

    assert cli_main([str(path), "--json", str(output)]) == 2
    captured = capsys.readouterr()
    assert "OUTPUT_WRITE_FAILED" in captured.err
    assert "Traceback" not in captured.out + captured.err
    assert output.read_text(encoding="utf-8") == "EXISTING-REPORT"
    assert not path.exists()
    swapped = list(tmp_path.glob(".inspect-ipa-*"))
    assert swapped
    assert any(item.read_bytes() == before for item in swapped)


def test_cli_output_parent_error_is_a_fixed_refusal(tmp_path: Path, capsys):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    output = tmp_path / "private-family-photos" / "missing-directory" / "report.json"

    assert cli_main([str(path), "--json", str(output)]) == 2
    captured = capsys.readouterr()
    assert "OUTPUT_WRITE_FAILED" in captured.err
    assert "private-family-photos" not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err


def test_cli_suppresses_temporary_cleanup_errors(tmp_path: Path, monkeypatch, capsys):
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())
    output = tmp_path / "report.json"
    real_unlink = cli_module.Path.unlink
    attempted: list[str] = []

    def failing_unlink(self, *args, **kwargs):
        attempted.append(str(self))
        if self.name.startswith(".inspect-ipa-"):
            raise OSError("cleanup denied")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(cli_module.Path, "unlink", failing_unlink)

    assert cli_main([str(path), "--json", str(output)]) == 0
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    assert output.is_file()
    assert any(Path(item).name.startswith(".inspect-ipa-") for item in attempted)
