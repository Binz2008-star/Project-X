"""Tests for the read-only, fail-closed build-manager preflight gate.

All payloads are synthetic. No IPA, credential, signing identity, device, or
network access is needed or used.
"""

from __future__ import annotations

import copy
import json

import pytest

from project_x.buildmanager import evaluate
from scripts.build_manager_preflight import main

SHA = "a" * 64
BUNDLE = "demo.owned"


def authorization_manifest() -> dict:
    return {
        "schema_version": "1.0",
        "owner_authorized": True,
        "authorization_id": "AUTH-DEMO-001",
        "expected_identity": {
            "bundle_id": BUNDLE,
            "version": "1.0.0",
            "build_number": "7",
        },
        "expected_sha256": SHA,
        "rights_basis": "owned-test-package",
    }


def slice_record() -> dict:
    return {
        "arch": "arm64",
        "cpu_type": 0x0100000C,
        "cpu_subtype": 0,
        "file_type": "MH_EXECUTE",
        "is_64_bit": True,
        "flags": 0,
        "load_command_count": 12,
        "min_os": "16.3",
        "sdk": "18.5",
        "rpaths": [],
        "dylibs": [],
        "encryption": {"cryptid": 0, "encrypted": False, "cryptoff": 0, "cryptsize": 0},
        "has_code_signature_load_command": True,
        "uuid": "00000000-0000-0000-0000-000000000000",
    }


def inspection_report() -> dict:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-11-21T00:00:00Z",
        "analyzer": {"name": "project-x-ipa", "version": "0.1.0"},
        "artifact": {
            "file_name": "private-demo.ipa",
            "size_bytes": 1024,
            "entry_count": 4,
            "uncompressed_bytes": 4096,
            "sha256": SHA,
        },
        "limits": {},
        "identity": {
            "bundle_id": BUNDLE,
            "name": "Owned Demo",
            "display_name": "Owned Demo",
            "version": "1.0.0",
            "build_number": "7",
            "minimum_os": "16.3",
            "executable": "Payload/demo.app/demo",
            "device_families": [1, 2],
            "supported_platforms": ["iOS"],
        },
        "macho": {
            "slice_count": 1,
            "is_universal": False,
            "architectures": ["arm64"],
            "slices": [slice_record()],
        },
        "bundles": {"extensions": [], "frameworks": [], "resource_bundles": [], "counts": {}},
        "signing": {
            "app_code_resources_present": True,
            "app_signature_file_count": 1,
            "provisioning_profile_present": False,
            "provisioning_profile": None,
            "fairplay_metadata_present": False,
            "nested_bundles_total": 0,
            "nested_bundles_signed": 0,
            "nested_bundles_unsigned": [],
            "verification": {"verified": False, "reason": "offline_static_inspection"},
        },
        "dependencies": {
            "frameworks": [],
            "rpath_dependencies": [],
            "executable_path_dependencies": [],
            "unresolved_rpath_dependencies": [],
            "protected_frameworks": [],
            "duplicate_framework_basenames": [],
        },
        "findings": [],
        "interpretation": {
            "note": "static structure only",
            "malware_verdict": None,
        },
    }


def codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


def test_authorized_owned_package_produces_dry_run_plan() -> None:
    result = evaluate(authorization_manifest(), inspection_report())
    assert result.preflight_passed is True
    assert result.plan is not None
    assert result.plan["mode"] == "dry_run"
    assert result.plan["execution_permitted"] is False
    assert result.plan["status"] == "READY_FOR_INDEPENDENT_REVIEW"
    assert result.plan["xinsta_core"]["install_name"] == "@rpath/libXinstaCore.dylib"
    assert result.plan["xinsta_core"]["hook"] is False
    assert result.plan["xinsta_core"]["swizzle"] is False
    blocked = {
        step["id"] for step in result.plan["steps"] if step["status"] == "blocked"
    }
    assert {
        "codesign_bundle_and_frameworks",
        "register_device_and_install",
        "verify_x_settings_in_host",
    } <= blocked
    assert all(credential["provided"] is False for credential in result.plan["required_credentials"])


def test_result_is_deterministic() -> None:
    first = evaluate(authorization_manifest(), inspection_report()).to_dict()
    second = evaluate(authorization_manifest(), inspection_report()).to_dict()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_cli_passes_and_prints_json(tmp_path, capsys) -> None:
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.json"
    manifest_path.write_text(json.dumps(authorization_manifest()), encoding="utf-8")
    report_path.write_text(json.dumps(inspection_report()), encoding="utf-8")
    assert main(["--manifest", str(manifest_path), "--report", str(report_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["preflight_passed"] is True
    assert payload["plan"]["execution_permitted"] is False


def test_cli_rejects_with_exit_code_two(tmp_path, capsys) -> None:
    report = inspection_report()
    report["identity"]["version"] = "2.0.0"
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.json"
    manifest_path.write_text(json.dumps(authorization_manifest()), encoding="utf-8")
    report_path.write_text(json.dumps(report), encoding="utf-8")
    assert main(["--manifest", str(manifest_path), "--report", str(report_path)]) == 2
    output = capsys.readouterr().out
    assert "VERSION_MISMATCH" in output
    assert json.loads(output)["plan"] is None


def test_cli_does_not_echo_private_paths(tmp_path, capsys) -> None:
    secret_dir = tmp_path / "private-family-photos"
    secret_dir.mkdir()
    assert main(["--manifest", str(secret_dir / "missing.json"), "--report", str(secret_dir / "x.json")]) == 1
    output = capsys.readouterr().out
    assert "private-family-photos" not in output
    assert "input_unreadable" in output


def test_third_party_bundle_is_always_rejected() -> None:
    manifest = authorization_manifest()
    manifest["expected_identity"]["bundle_id"] = "com.burbn.instagram"
    report = inspection_report()
    report["identity"]["bundle_id"] = "com.burbn.instagram"
    result = evaluate(manifest, report)
    assert result.preflight_passed is False
    assert "BUNDLE_ID_NOT_ALLOWED" in codes(result)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update(owner_authorized=False),
        lambda m: m.update(owner_authorized="true"),
        lambda m: m.update(schema_version="2.0"),
        lambda m: m.update(extra_field="ignored"),
        lambda m: m.update(expected_sha256="A" * 64),
        lambda m: m["expected_identity"].update(version="*"),
        lambda m: m.update(rights_basis="downloaded-from-app-store"),
        lambda m: m.update(authorization_id="x"),
    ],
)
def test_invalid_manifest_is_rejected(mutate) -> None:
    manifest = authorization_manifest()
    mutate(manifest)
    result = evaluate(manifest, inspection_report())
    assert result.preflight_passed is False
    assert "MANIFEST_INVALID" in codes(result)


def test_missing_manifest_key_is_rejected() -> None:
    manifest = authorization_manifest()
    del manifest["rights_basis"]
    result = evaluate(manifest, inspection_report())
    assert "MANIFEST_INVALID" in codes(result)


def test_report_schema_must_match() -> None:
    report = inspection_report()
    report["schema_version"] = "2.0"
    result = evaluate(authorization_manifest(), report)
    assert "REPORT_INVALID" in codes(result)


def test_report_identity_must_be_present() -> None:
    report = inspection_report()
    del report["identity"]["build_number"]
    result = evaluate(authorization_manifest(), report)
    assert "REPORT_INVALID" in codes(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bundle_id", "demo.other"),
        ("version", "9.9.9"),
        ("build_number", "8"),
    ],
)
def test_identity_mismatch_is_rejected(field, value) -> None:
    report = inspection_report()
    report["identity"][field] = value
    result = evaluate(authorization_manifest(), report)
    assert result.preflight_passed is False
    expected = {
        "bundle_id": "BUNDLE_ID_MISMATCH",
        "version": "VERSION_MISMATCH",
        "build_number": "BUILD_MISMATCH",
    }[field]
    assert expected in codes(result)


def test_hash_mismatch_is_rejected() -> None:
    report = inspection_report()
    report["artifact"]["sha256"] = "b" * 64
    result = evaluate(authorization_manifest(), report)
    assert "SHA256_MISMATCH" in codes(result)


@pytest.mark.parametrize("value", ["15.0", None, "unknown", "16"])
def test_too_low_or_invalid_minimum_os_is_rejected(value) -> None:
    report = inspection_report()
    report["identity"]["minimum_os"] = value
    result = evaluate(authorization_manifest(), report)
    assert "MINIMUM_OS_TOO_LOW" in codes(result)


def test_missing_main_executable_is_rejected() -> None:
    report = inspection_report()
    report["identity"]["executable"] = None
    result = evaluate(authorization_manifest(), report)
    assert "MAIN_EXECUTABLE_MISSING" in codes(result)


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (lambda s: s.update(arch="x86_64"), "MAIN_EXECUTABLE_ARCHITECTURE"),
        (lambda s: s.update(is_64_bit=False), "MAIN_EXECUTABLE_NOT_64_BIT"),
        (lambda s: s.update(file_type="MH_DYLIB"), "MAIN_EXECUTABLE_FILE_TYPE"),
        (lambda s: s["encryption"].update(cryptid=1), "MAIN_EXECUTABLE_ENCRYPTED"),
        (lambda s: s.update(encryption=None), "MAIN_EXECUTABLE_ENCRYPTED"),
        (lambda s: s["encryption"].update(cryptid=False), "MAIN_EXECUTABLE_ENCRYPTED"),
    ],
)
def test_unsafe_main_executable_slice_is_rejected(mutate, expected_code) -> None:
    report = inspection_report()
    mutate(report["macho"]["slices"][0])
    result = evaluate(authorization_manifest(), report)
    assert expected_code in codes(result)


def test_no_slices_is_rejected() -> None:
    report = inspection_report()
    report["macho"]["slices"] = []
    result = evaluate(authorization_manifest(), report)
    assert "MAIN_EXECUTABLE_SLICES_MISSING" in codes(result)


def test_critical_analysis_finding_is_rejected() -> None:
    report = inspection_report()
    report["findings"] = [{"code": "PATH_TRAVERSAL", "severity": "critical", "detail": "x"}]
    result = evaluate(authorization_manifest(), report)
    assert "CRITICAL_ANALYSIS_FINDING" in codes(result)
    assert any("PATH_TRAVERSAL" in finding.detail for finding in result.findings)


def test_warning_findings_become_review_items() -> None:
    report = inspection_report()
    report["findings"] = [{"code": "SYMLINK_ENTRY", "severity": "warning", "detail": "x"}]
    report["dependencies"]["duplicate_framework_basenames"] = ["Foo.framework"]
    result = evaluate(authorization_manifest(), report)
    assert result.preflight_passed is True
    assert result.plan["review_findings"] == ["DUPLICATE_FRAMEWORK_BASENAME", "SYMLINK_ENTRY"]


def test_signing_verification_claim_is_rejected() -> None:
    report = inspection_report()
    report["signing"]["verification"]["verified"] = True
    result = evaluate(authorization_manifest(), report)
    assert "SIGNING_VERIFICATION_CLAIM" in codes(result)


def test_malware_verdict_claim_is_rejected() -> None:
    report = inspection_report()
    report["interpretation"]["malware_verdict"] = "clean"
    result = evaluate(authorization_manifest(), report)
    assert "MALWARE_VERDICT_CLAIM" in codes(result)


def test_unresolved_rpath_dependency_is_rejected() -> None:
    report = inspection_report()
    report["dependencies"]["unresolved_rpath_dependencies"] = ["@rpath/Missing.framework/Missing"]
    result = evaluate(authorization_manifest(), report)
    assert "UNRESOLVED_RPATH_DEPENDENCY" in codes(result)


def test_output_contains_no_secret_values_or_local_paths() -> None:
    manifest = authorization_manifest()
    manifest["authorization_id"] = "AUTH-DEMO-001"
    report = inspection_report()
    report["artifact"]["file_name"] = "C:\\Users\\owner\\Private\\Instagram.ipa"
    report["signing"]["provisioning_profile"] = {
        "name": "SUPER-SECRET-PROFILE-NAME",
        "team_identifiers": ["TEAMSECRET"],
    }
    result = evaluate(manifest, report)
    assert result.preflight_passed is True
    output = json.dumps(result.to_dict())
    assert "SUPER-SECRET-PROFILE-NAME" not in output
    assert "TEAMSECRET" not in output
    assert "C:\\Users\\owner" not in output


def test_multiple_blockers_are_reported_together() -> None:
    manifest = authorization_manifest()
    report = inspection_report()
    report["identity"]["version"] = "2.0.0"
    report["artifact"]["sha256"] = "b" * 64
    report["macho"]["slices"][0]["arch"] = "x86_64"
    result = evaluate(manifest, report)
    assert {"VERSION_MISMATCH", "SHA256_MISMATCH", "MAIN_EXECUTABLE_ARCHITECTURE"} <= codes(result)
    assert result.plan is None


def test_inputs_are_not_mutated() -> None:
    manifest = authorization_manifest()
    report = inspection_report()
    manifest_before = copy.deepcopy(manifest)
    report_before = copy.deepcopy(report)
    evaluate(manifest, report)
    assert manifest == manifest_before
    assert report == report_before


def test_unknown_analysis_code_cannot_leak_into_output() -> None:
    secret_code = "C:\\Users\\owner\\private-family-photos\\SECRET\\nSECOND LINE"
    for severity in ("warning", "critical"):
        report = inspection_report()
        report["findings"] = [{"code": secret_code, "severity": severity, "detail": "x"}]
        result = evaluate(authorization_manifest(), report)
        assert result.preflight_passed is False
        assert "REPORT_INVALID" in codes(result)
        assert secret_code not in json.dumps(result.to_dict())


def test_unknown_manifest_key_name_cannot_leak_into_output() -> None:
    manifest = authorization_manifest()
    manifest["SUPER_SECRET_PROFILE_NAME"] = "value"
    result = evaluate(manifest, inspection_report())
    assert "MANIFEST_INVALID" in codes(result)
    output = json.dumps(result.to_dict())
    assert "SUPER_SECRET_PROFILE_NAME" not in output
    assert "value" not in output


def test_cli_rejects_extra_arguments_without_echoing_paths(capsys) -> None:
    private = "--extra C:\\Users\\owner\\private-family-photos\\secret.json"
    assert main(private.split()) == 1
    captured = capsys.readouterr()
    assert "private-family-photos" not in captured.out + captured.err
    assert json.loads(captured.out) == {"error": "invalid_arguments"}


def test_cli_rejects_missing_arguments_without_echoing_paths(capsys) -> None:
    private = "--report C:\\Users\\owner\\private-family-photos\\missing-report.json"
    assert main(private.split()) == 1
    captured = capsys.readouterr()
    assert "private-family-photos" not in captured.out + captured.err
    assert json.loads(captured.out) == {"error": "invalid_arguments"}


def test_arm64e_slice_is_accepted() -> None:
    report = inspection_report()
    report["macho"]["slices"][0]["arch"] = "arm64e"
    result = evaluate(authorization_manifest(), report)
    assert result.preflight_passed is True


def test_slice_count_mismatch_is_rejected() -> None:
    report = inspection_report()
    report["macho"]["slice_count"] = 2
    result = evaluate(authorization_manifest(), report)
    assert "MACHO_SLICE_COUNT_MISMATCH" in codes(result)


@pytest.mark.parametrize("value", ["A" * 64, "short", None, "b" * 63])
def test_report_hash_uses_the_same_strict_format(value) -> None:
    report = inspection_report()
    report["artifact"]["sha256"] = value
    result = evaluate(authorization_manifest(), report)
    assert "REPORT_INVALID" in codes(result)
