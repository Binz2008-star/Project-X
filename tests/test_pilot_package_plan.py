"""Tests for the fail-closed private-pilot packaging planner.

All inputs are local synthetic fixtures. No Instagram IPA, signing material or
device is used.
"""
from __future__ import annotations

import hashlib
import plistlib

import pytest

import project_x.packaging.pilot_plan as planner
import scripts.pilot_package_plan as cli
from tests.ipa_fixtures import (
    APP,
    CPU_X86_64,
    LC_ID_DYLIB,
    LC_LOAD_DYLIB,
    MH_DYLIB,
    MH_EXECUTE,
    base_entries,
    build_macho,
    owned_info,
    write_ipa,
)


def _source_info() -> dict:
    info = owned_info()
    info.update(
        CFBundleIdentifier="com.burbn.instagram",
        CFBundleShortVersionString="456.0.0",
        CFBundleVersion="1114925422",
    )
    info["CFBundleURLTypes"] = [
        {"CFBundleURLSchemes": ["instagram", "fb124024574287414production"]}
    ]
    return info


def _source_ipa(tmp_path, *, info: dict | None = None):
    entries = base_entries(executable=build_macho(), info=info or _source_info())
    extension = APP + "PlugIns/Share.appex/"
    entries[extension + "Info.plist"] = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.burbn.instagram.shareextension",
            "CFBundleName": "Share",
            "CFBundleDisplayName": "Share",
            "CFBundleShortVersionString": "456.0.0",
            "CFBundleVersion": "1114925422",
            "MinimumOSVersion": "16.3",
            "CFBundleExecutable": "Share",
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
        },
        fmt=plistlib.FMT_BINARY,
    )
    entries[extension + "Share"] = build_macho()
    path = write_ipa(tmp_path / "pinned-source.ipa", entries)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _dylib(*, file_type: int = MH_DYLIB, cpu_type: int | None = None, install_name: str = "@rpath/libXinstaCore.dylib"):
    return build_macho(
        file_type=file_type,
        cpu_type=cpu_type if cpu_type is not None else 0x0100000C,
        dylibs=(
            (install_name, LC_ID_DYLIB),
            ("/usr/lib/libSystem.B.dylib", LC_LOAD_DYLIB),
        ),
    )


def test_plan_is_deterministic_and_dry_run(tmp_path, monkeypatch) -> None:
    ipa, digest = _source_ipa(tmp_path)
    monkeypatch.setattr(planner, "PRIVATE_PILOT_SOURCE_SHA256", digest)
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(_dylib())

    first = planner.build_pilot_package_plan(ipa, dylib)
    second = planner.build_pilot_package_plan(ipa, dylib)

    assert first == second
    assert planner.plan_json(first) == planner.plan_json(second)
    assert first["mode"] == "dry_run"
    assert first["execution_permitted"] is False
    assert first["source"]["sha256"] == digest
    assert first["source"]["extension_count"] == 1
    assert first["dylib"]["dependencies"] == "system_only"
    assert first["pilot_identity"]["bundle_id"] == "com.projectx.xinsta.pilot"
    assert first["verification"]["hook"] is False
    assert first["verification"]["swizzle"] is False
    assert {step["code"] for step in first["planned_changes"]}
    assert {step["code"] for step in first["blocked_steps"]}


def test_wrong_source_hash_is_rejected(tmp_path, monkeypatch) -> None:
    ipa, _ = _source_ipa(tmp_path)
    monkeypatch.setattr(planner, "PRIVATE_PILOT_SOURCE_SHA256", "0" * 64)
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(_dylib())

    with pytest.raises(planner.PilotPlanError) as caught:
        planner.build_pilot_package_plan(ipa, dylib)
    assert caught.value.code == "SOURCE_HASH_MISMATCH"


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"file_type": MH_EXECUTE}, "DYLIB_FILE_TYPE_MISMATCH"),
        ({"cpu_type": CPU_X86_64}, "DYLIB_ARCH_MISMATCH"),
        ({"install_name": "@rpath/wrong.dylib"}, "DYLIB_ID_MISMATCH"),
    ],
)
def test_invalid_dylib_is_rejected(tmp_path, monkeypatch, kwargs, expected) -> None:
    ipa, digest = _source_ipa(tmp_path)
    monkeypatch.setattr(planner, "PRIVATE_PILOT_SOURCE_SHA256", digest)
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(_dylib(**kwargs))

    with pytest.raises(planner.PilotPlanError) as caught:
        planner.build_pilot_package_plan(ipa, dylib)
    assert caught.value.code == expected


def test_cli_reports_fixed_error_without_path_echo(capsys) -> None:
    code = cli.main(["--ipa", "private-path.ipa", "--dylib", "private-path.dylib"])
    output = capsys.readouterr().out

    assert code == 2
    assert "SOURCE_INSPECTION_FAILED" in output
    assert "private-path" not in output
