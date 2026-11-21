"""Tests for the bounded unsigned pilot-package builder.

All fixtures are synthetic. No third-party IPA, signing identity, credential, or
device is used. The builder is expected to stop before signing or installation.
"""
from __future__ import annotations

import hashlib
import plistlib
import struct
import zipfile

import pytest

import project_x.packaging.pilot_plan as planner
import scripts.pilot_package_build as build_cli
from project_x.ipa import inspect_ipa, sha256_of_file
from project_x.ipa.macho import (
    LC_CODE_SIGNATURE,
    LC_LOAD_DYLIB,
    LC_SEGMENT_64,
    MH_MAGIC_64,
    MachOError,
    parse_macho,
)
from project_x.packaging.builder import PilotBuildError, build_unsigned_pilot_ipa
from project_x.packaging.macho_patch import add_load_dylib
from tests.ipa_fixtures import APP, MH_DYLIB, base_entries, build_macho, write_ipa


def _source_info() -> dict:
    info = {
        "CFBundleIdentifier": "com.burbn.instagram",
        "CFBundleName": "Instagram",
        "CFBundleDisplayName": "Instagram",
        "CFBundleShortVersionString": "456.0.0",
        "CFBundleVersion": "1114925422",
        "MinimumOSVersion": "16.3",
        "CFBundleExecutable": "Demo",
        "UIDeviceFamily": [1],
        "CFBundleSupportedPlatforms": ["iPhoneOS"],
        "CFBundleURLTypes": [
            {"CFBundleURLSchemes": ["instagram", "fb124024574287414production"]}
        ],
    }
    return info


def _source_ipa(tmp_path):
    main_executable = build_macho(rpaths=("@executable_path/Frameworks",))
    main_executable += b"\x00" * 0x1000
    entries = base_entries(executable=main_executable, info=_source_info())
    extension = APP + "PlugIns/Share.appex/"
    entries[extension + "Info.plist"] = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.burbn.instagram.shareextension",
            "CFBundleName": "Share",
            "CFBundleExecutable": "Share",
            "CFBundleShortVersionString": "456.0.0",
            "CFBundleVersion": "1114925422",
            "MinimumOSVersion": "16.3",
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        },
        fmt=plistlib.FMT_BINARY,
    )
    entries[APP + "PlugIns/"] = b""
    entries[extension + "Share"] = build_macho()
    entries[APP + "embedded.mobileprovision"] = plistlib.dumps(
        {
            "Entitlements": {
                "application-identifier": "TEAM123.com.burbn.instagram",
                "com.apple.security.application-groups": ["group.com.burbn.instagram.shared"],
                "com.apple.developer.associated-domains": ["applinks:example.invalid"],
                "get-task-allow": True,
            }
        },
        fmt=plistlib.FMT_XML,
    )
    path = write_ipa(tmp_path / "source.ipa", entries)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _dylib():
    return build_macho(
        file_type=MH_DYLIB,
        cpu_type=0x0100000C,
        dylibs=(
            ("@rpath/libXinstaCore.dylib", 0xD),
            ("/usr/lib/libSystem.B.dylib", LC_LOAD_DYLIB),
        ),
    )


def _pin_fixtures(monkeypatch, source_hash: str, dylib_data: bytes) -> None:
    monkeypatch.setattr(planner, "PRIVATE_PILOT_SOURCE_SHA256", source_hash)
    monkeypatch.setattr(
        planner, "PRIVATE_PILOT_DYLIB_SHA256", hashlib.sha256(dylib_data).hexdigest()
    )
    # The synthetic source carries a stale associated-domains entitlement so the
    # builder's removal can be asserted. The planner intentionally rejects that
    # entitlement in real Instagram input, so point its check at an unused key.
    monkeypatch.setattr(planner, "ASSOCIATED_DOMAINS_ENTITLEMENT", "test.unused.entitlement")


def test_build_creates_distinct_unsigned_pilot_ipa(tmp_path, monkeypatch) -> None:
    source, source_hash = _source_ipa(tmp_path)
    dylib_data = _dylib()
    _pin_fixtures(monkeypatch, source_hash, dylib_data)
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(dylib_data)
    output = tmp_path / "Xinsta.ipa"

    result = build_unsigned_pilot_ipa(
        source, dylib, output, rights_reference="PILOT-RIGHTS-1"
    )

    assert result["signed"] is False
    assert result["signature_status"] == "invalidated_requires_resign"
    assert result["source_sha256"] == source_hash
    assert result["output_sha256"] != source_hash
    assert output.exists()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash

    report = inspect_ipa(str(output))
    assert report.identity.bundle_id == "com.projectx.xinsta.pilot"
    assert report.identity.display_name == "Xinsta"
    assert report.identity.url_schemes == ("xinsta-pilot-loadproof",)
    assert len(report.bundles["extensions"]) == 1
    assert report.bundles["extensions"][0].bundle_id == (
        "com.projectx.xinsta.pilot.shareextension"
    )
    assert any(ref.name == "@rpath/libXinstaCore.dylib" for ref in report.macho_slices[0].dylibs)

    with zipfile.ZipFile(output) as archive:
        assert APP + "PlugIns/" in archive.namelist()
        assert APP + "Frameworks/libXinstaCore.dylib" in archive.namelist()
        profile = plistlib.loads(archive.read(APP + "embedded.mobileprovision"))
        entitlements = profile["Entitlements"]
        assert entitlements["application-identifier"] == "TEAM123.com.projectx.xinsta.pilot"
        assert entitlements["com.apple.security.application-groups"] == [
            "group.com.projectx.xinsta.pilot.shared"
        ]
        assert "com.apple.developer.associated-domains" not in entitlements


def test_build_requires_rights_reference(tmp_path, monkeypatch) -> None:
    source, source_hash = _source_ipa(tmp_path)
    dylib_data = _dylib()
    _pin_fixtures(monkeypatch, source_hash, dylib_data)
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(dylib_data)

    with pytest.raises(PilotBuildError) as caught:
        build_unsigned_pilot_ipa(source, dylib, tmp_path / "Xinsta.ipa")
    assert caught.value.code == "RIGHTS_REFERENCE_REQUIRED"
    assert not (tmp_path / "Xinsta.ipa").exists()


@pytest.mark.parametrize("reference", ["me@example.invalid", "pwd=secret", "a b", ""])
def test_build_rejects_unsafe_rights_reference(tmp_path, reference) -> None:
    source = tmp_path / "source.ipa"
    source.write_bytes(b"unused")
    dylib = tmp_path / "dylib"
    dylib.write_bytes(b"unused")

    with pytest.raises(PilotBuildError) as caught:
        build_unsigned_pilot_ipa(
            source, dylib, tmp_path / "Xinsta.ipa", rights_reference=reference
        )
    assert caught.value.code in {"RIGHTS_REFERENCE_REQUIRED", "RIGHTS_REFERENCE_INVALID"}


def _seg_text64(section_offset: int) -> bytes:
    segment = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        72 + 80,
        b"__TEXT",
        0,
        0x4000,
        0,
        0x4000,
        7,
        5,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text",
        b"__TEXT",
        0x100008000,
        0x100,
        section_offset,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    return segment + section


def _symtab(symoff: int, stroff: int) -> bytes:
    return struct.pack("<IIIIII", 0x2, 24, symoff, 1, stroff, 0x10)


def _code_signature(dataoff: int) -> bytes:
    return struct.pack("<IIII", LC_CODE_SIGNATURE, 16, dataoff, 0x100)


def _lc_main(entryoff: int) -> bytes:
    return struct.pack("<IIQQ", 0x80000028, 24, entryoff, 0)


def _padded_image(commands: list[bytes], content_start: int, content: bytes) -> bytes:
    body = b"".join(commands)
    header = struct.pack(
        "<IiiIIIII", MH_MAGIC_64, 0x0100000C, 0, 2, len(commands), len(body), 0, 0
    )
    prefix = header + body
    assert len(prefix) <= content_start
    return prefix + b"\x00" * (content_start - len(prefix)) + content


def _commands_end(image: bytes) -> int:
    sizeofcmds = struct.unpack_from("<I", image, 20)[0]
    return 32 + sizeofcmds


def test_add_load_dylib_appends_into_padding_without_relocation() -> None:
    commands = [
        _seg_text64(0x4000),
        _symtab(0x4100, 0x4200),
        _code_signature(0x4300),
        _lc_main(0x4010),
    ]
    image = _padded_image(commands, 0x4000, b"\xAA" * 0x400)
    old_end = _commands_end(image)

    patched = add_load_dylib(image, "@rpath/libXinstaCore.dylib")

    new_size = 56
    magic, _cpu, _sub, _type, ncmds, sizeofcmds, _flags, _reserved = struct.unpack_from(
        "<IiiIIIII", patched
    )
    assert magic == MH_MAGIC_64
    assert ncmds == len(commands) + 1
    assert sizeofcmds == _commands_end(image) - 32 + new_size
    assert len(patched) == len(image)

    # Only the header fields and the appended command differ; every other byte
    # is identical, so no file offset, VM address or signature position moved.
    assert patched[32:old_end] == image[32:old_end]
    assert patched[old_end + new_size :] == image[old_end + new_size :]
    command, command_size, name_offset = struct.unpack_from("<III", patched, old_end)
    assert command == LC_LOAD_DYLIB
    assert command_size == new_size
    assert patched[old_end + name_offset :].split(b"\x00", 1)[0] == (
        b"@rpath/libXinstaCore.dylib"
    )

    # Referenced file offsets are bit-identical to the source image.
    assert struct.unpack_from("<I", patched, 32 + 72 + 48)[0] == 0x4000
    assert struct.unpack_from("<I", patched, 32 + 72 + 80 + 8)[0] == 0x4100
    assert struct.unpack_from("<I", patched, 32 + 72 + 80 + 24 + 8)[0] == 0x4300
    assert struct.unpack_from("<Q", patched, 32 + 72 + 80 + 24 + 16 + 8)[0] == 0x4010
    assert any(
        ref.name == "@rpath/libXinstaCore.dylib" for ref in parse_macho(patched)[0].dylibs
    )


def test_add_load_dylib_rejects_insufficient_padding() -> None:
    commands = [_seg_text64(0), _symtab(0, 0), _code_signature(0), _lc_main(0)]
    body_len = sum(len(command) for command in commands)
    tight_offset = 32 + body_len + 16
    commands[0] = _seg_text64(tight_offset)
    image = _padded_image(commands, tight_offset, b"\xAA" * 0x100)

    with pytest.raises(MachOError):
        add_load_dylib(image, "@rpath/libXinstaCore.dylib")


def test_add_load_dylib_rejects_nonzero_padding() -> None:
    commands = [_seg_text64(0x4000)]
    image = bytearray(_padded_image(commands, 0x4000, b"\xAA" * 0x400))
    image[_commands_end(bytes(image))] = 0xFF

    with pytest.raises(MachOError):
        add_load_dylib(bytes(image), "@rpath/libXinstaCore.dylib")


def test_add_load_dylib_rejects_file_offset_collision() -> None:
    commands = [_seg_text64(0x4000)]
    body_len = sum(len(command) for command in commands)
    symtab = _symtab(0, 0)
    commands.append(symtab)
    commands_end = 32 + body_len + len(symtab)
    colliding = commands_end + 8
    commands[-1] = _symtab(colliding, 0)
    image = _padded_image(commands, 0x4000, b"\xAA" * 0x400)

    with pytest.raises(MachOError):
        add_load_dylib(image, "@rpath/libXinstaCore.dylib")


def test_add_load_dylib_rejects_unknown_command() -> None:
    unknown = struct.pack("<II", 0x9999, 16) + b"\x00" * 8
    image = _padded_image([unknown], 0x4000, b"\xAA" * 0x400)

    with pytest.raises(MachOError):
        add_load_dylib(image, "@rpath/libXinstaCore.dylib")


def test_add_load_dylib_rejects_fileset_entries() -> None:
    fileset_entry = struct.pack("<III", 0x80000035, 12, 0)
    header = struct.pack(
        "<IiiIIIII", MH_MAGIC_64, 0x0100000C, 0, 2, 1, len(fileset_entry), 0, 0
    )

    with pytest.raises(MachOError):
        add_load_dylib(header + fileset_entry + b"x" * 0x100, "@rpath/libXinstaCore.dylib")


def test_sha256_of_file_returns_raw_file_digest(tmp_path) -> None:
    path = write_ipa(tmp_path / "Demo.ipa", base_entries())

    assert sha256_of_file(str(path)) == hashlib.sha256(path.read_bytes()).hexdigest()


def test_cli_reports_fixed_error_without_path_echo(capsys) -> None:
    code = build_cli.main(
        [
            "--ipa",
            "private-path.ipa",
            "--dylib",
            "private-path.dylib",
            "--output",
            "private-output.ipa",
            "--rights-reference",
            "PILOT-RIGHTS-1",
        ]
    )
    output = capsys.readouterr().out

    assert code == 2
    assert "SOURCE_INSPECTION_FAILED" in output
    assert "private-" not in output
