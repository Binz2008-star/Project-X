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
    LC_LOAD_WEAK_DYLIB,
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


def _source_ipa(tmp_path, *, info: dict | None = None, executable: bytes | None = None):
    main_executable = executable or build_macho(rpaths=("@executable_path/Frameworks",))
    entries = base_entries(executable=main_executable, info=info or _source_info())
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
    dylib_data = _dylib()
    monkeypatch.setattr(
        planner, "PRIVATE_PILOT_DYLIB_SHA256", hashlib.sha256(dylib_data).hexdigest()
    )
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(dylib_data)

    first = planner.build_pilot_package_plan(ipa, dylib)
    second = planner.build_pilot_package_plan(ipa, dylib)

    assert first == second
    assert planner.plan_json(first) == planner.plan_json(second)
    assert first["mode"] == "dry_run"
    assert first["execution_permitted"] is False
    assert first["source"]["sha256"] == digest
    assert first["source"]["extension_count"] == 1
    assert first["source"]["main_executable_rpaths"] == ["@executable_path/Frameworks"]
    assert first["source"]["core_load_command_present"] is False
    assert first["source"]["signing_metadata"]["verification_claimed"] is False
    assert first["dylib"]["dependencies"] == "system_only"
    assert first["pilot_identity"]["bundle_id"] == "com.projectx.xinsta.pilot"
    assert first["pilot_identity"]["display_name"] == "Xinsta"
    rpath_step = next(
        step for step in first["planned_changes"] if step["code"] == "ENSURE_DYLIB_RPATH"
    )
    assert rpath_step["status"] == "already_present"
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


@pytest.mark.parametrize("load_command", [LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB])
def test_existing_core_load_command_is_rejected(
    tmp_path, monkeypatch, load_command
) -> None:
    executable = build_macho(
        rpaths=("@executable_path/Frameworks",),
        dylibs=(
            ("@rpath/libXinstaCore.dylib", load_command),
            ("/usr/lib/libSystem.B.dylib", LC_LOAD_DYLIB),
        ),
    )
    ipa, digest = _source_ipa(tmp_path, executable=executable)
    monkeypatch.setattr(planner, "PRIVATE_PILOT_SOURCE_SHA256", digest)
    dylib_data = _dylib()
    monkeypatch.setattr(
        planner, "PRIVATE_PILOT_DYLIB_SHA256", hashlib.sha256(dylib_data).hexdigest()
    )
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(dylib_data)

    with pytest.raises(planner.PilotPlanError) as caught:
        planner.build_pilot_package_plan(ipa, dylib)
    assert caught.value.code == "SOURCE_CORE_LOAD_COMMAND_PRESENT"


def test_duplicate_core_rpath_is_rejected(tmp_path, monkeypatch) -> None:
    executable = build_macho(
        rpaths=("@executable_path/Frameworks", "@executable_path/Frameworks")
    )
    ipa, digest = _source_ipa(tmp_path, executable=executable)
    monkeypatch.setattr(planner, "PRIVATE_PILOT_SOURCE_SHA256", digest)
    dylib_data = _dylib()
    monkeypatch.setattr(
        planner, "PRIVATE_PILOT_DYLIB_SHA256", hashlib.sha256(dylib_data).hexdigest()
    )
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(dylib_data)

    with pytest.raises(planner.PilotPlanError) as caught:
        planner.build_pilot_package_plan(ipa, dylib)
    assert caught.value.code == "SOURCE_RPATH_DUPLICATE"


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
    dylib_data = _dylib(**kwargs)
    monkeypatch.setattr(
        planner, "PRIVATE_PILOT_DYLIB_SHA256", hashlib.sha256(dylib_data).hexdigest()
    )
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(dylib_data)

    with pytest.raises(planner.PilotPlanError) as caught:
        planner.build_pilot_package_plan(ipa, dylib)
    assert caught.value.code == expected


def test_wrong_dylib_hash_is_rejected(tmp_path, monkeypatch) -> None:
    ipa, digest = _source_ipa(tmp_path)
    monkeypatch.setattr(planner, "PRIVATE_PILOT_SOURCE_SHA256", digest)
    monkeypatch.setattr(planner, "PRIVATE_PILOT_DYLIB_SHA256", "0" * 64)
    dylib = tmp_path / "libXinstaCore.dylib"
    dylib.write_bytes(_dylib())

    with pytest.raises(planner.PilotPlanError) as caught:
        planner.build_pilot_package_plan(ipa, dylib)
    assert caught.value.code == "DYLIB_HASH_MISMATCH"


def test_cli_reports_fixed_error_without_path_echo(capsys) -> None:
    code = cli.main(["--ipa", "private-path.ipa", "--dylib", "private-path.dylib"])
    output = capsys.readouterr().out

    assert code == 2
    assert "SOURCE_INSPECTION_FAILED" in output
    assert "private-path" not in output
