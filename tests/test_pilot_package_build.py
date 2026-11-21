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


def test_add_load_dylib_relocates_file_offsets() -> None:
    segment_size = 72 + 80
    segment = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        segment_size,
        b"__TEXT",
        0,
        0x1000,
        0x1000,
        0x500,
        7,
        5,
        1,
        0,
    ) + struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text",
        b"__TEXT",
        0,
        0x100,
        0x1000,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    signature = struct.pack("<III", LC_CODE_SIGNATURE, 12, 0x2000)
    commands = segment + signature
    header = struct.pack(
        "<IiiIIIII", MH_MAGIC_64, 0x0100000C, 0, 2, 2, len(commands), 0, 0
    )
    original = header + commands + b"x" * 0x3000

    patched = add_load_dylib(original, "@rpath/libXinstaCore.dylib")
    magic, _cpu, _sub, _type, ncmds, sizeofcmds, _flags, _reserved = struct.unpack_from(
        "<IiiIIIII", patched
    )
    assert magic == MH_MAGIC_64
    assert ncmds == 3
    assert sizeofcmds == len(commands) + 56

    assert struct.unpack_from("<Q", patched, 32 + 40)[0] == 0x1000 + 56
    assert struct.unpack_from("<I", patched, 32 + 72 + 48)[0] == 0x1000 + 56
    assert struct.unpack_from("<I", patched, 32 + segment_size + 8)[0] == 0x2000 + 56
    assert any(ref.name == "@rpath/libXinstaCore.dylib" for ref in parse_macho(patched)[0].dylibs)


def test_add_load_dylib_preserves_header_segment_mapping() -> None:
    text = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        72,
        b"__TEXT",
        0,
        0x1000,
        0,
        0x1000,
        7,
        5,
        0,
        0,
    )
    linkedit = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        72,
        b"__LINKEDIT",
        0x1000,
        0x1000,
        0x2000,
        0x100,
        7,
        5,
        0,
        0,
    )
    chained_fixups = struct.pack("<III", 0x80000034, 12, 0x2100)
    exports_trie = struct.pack("<III", 0x80000033, 12, 0x2200)
    commands = text + linkedit + chained_fixups + exports_trie
    header = struct.pack(
        "<IiiIIIII", MH_MAGIC_64, 0x0100000C, 0, 2, 4, len(commands), 0, 0
    )

    patched = add_load_dylib(header + commands + b"x" * 0x3000, "@rpath/libXinstaCore.dylib")

    delta = 56
    assert struct.unpack_from("<Q", patched, 32 + 40)[0] == 0
    assert struct.unpack_from("<Q", patched, 32 + 48)[0] == 0x1000 + delta
    linkedit_base = 32 + 72
    assert struct.unpack_from("<Q", patched, linkedit_base + 40)[0] == 0x2000 + delta
    assert struct.unpack_from("<Q", patched, linkedit_base + 48)[0] == 0x100
    assert struct.unpack_from("<I", patched, 32 + 144 + 8)[0] == 0x2100 + delta
    assert struct.unpack_from("<I", patched, 32 + 156 + 8)[0] == 0x2200 + delta


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
