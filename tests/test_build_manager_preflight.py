"""Tests for the read-only, fail-closed build-manager preflight gate.

All payloads are synthetic. No IPA, credential, signing identity, device, or
network access is needed or used.
"""

from __future__ import annotations

import copy
import json
import struct
from pathlib import Path

import pytest

from project_x.buildmanager import (
    ACCEPTED_REPORT_SCHEMA_VERSIONS,
    EXPECTED_SEVERITIES,
    REPORT_INCONSISTENT_CODE,
    UNSAFE_IDENTITY_CODE,
    evaluate,
)
from project_x.buildmanager.preflight import KNOWN_ANALYSIS_CODES
from scripts.build_manager_preflight import (
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    main,
)

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE = 2

SHA = "a" * 64
BUNDLE = "demo.owned"
IG456_BUNDLE = "com.burbn.instagram"
IG456_VERSION = "456.0.0"
IG456_BUILD = "1114925422"
IG456_SHA = "665a814e13d8c187dce5a78d0e8348f73f9081205b927291d7d5d2bce96eb131"
IG456_ADAPTER = "com.burbn.instagram@456.0.0@1114925422"


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


def load_only_manifest() -> dict:
    manifest = authorization_manifest()
    manifest["authorization_id"] = "AUTH-IG456-LOAD-001"
    manifest["expected_identity"] = {
        "bundle_id": IG456_BUNDLE,
        "version": IG456_VERSION,
        "build_number": IG456_BUILD,
    }
    manifest["expected_sha256"] = IG456_SHA
    manifest["rights_basis"] = "load-only-proof"
    return manifest


def load_only_report() -> dict:
    report = inspection_report()
    report["artifact"]["sha256"] = IG456_SHA
    report["identity"].update(
        bundle_id=IG456_BUNDLE,
        name="Owner Authorized Target",
        display_name="Owner Authorized Target",
        version=IG456_VERSION,
        build_number=IG456_BUILD,
        executable="Payload/Target.app/Target",
    )
    return report


def macho_header_bytes(cpu_type: int, cpu_subtype: int, file_type: int = MH_EXECUTE) -> bytes:
    """A minimal, real 64-bit Mach-O header; no IPA is opened or modified."""
    return struct.pack(
        "<8I",
        MH_MAGIC_64,
        cpu_type,
        cpu_subtype,
        file_type,
        0,
        0,
        0,
        0,
    )


def slice_from_header(blob: bytes, *, arch: str | None = None) -> dict:
    """Turn real Mach-O header bytes into a versioned report slice record."""
    magic, cpu_type, cpu_subtype, file_type, *_rest = struct.unpack("<8I", blob)
    assert magic == MH_MAGIC_64
    subtype_names = {0: "arm64", 1: "arm64", 2: "arm64e"}
    if arch is None:
        arch = subtype_names.get(cpu_subtype)
        if arch is None:
            arch = "arm64" if cpu_type == CPU_TYPE_ARM64 else "x86_64"
    record = slice_record()
    record.update(
        arch=arch,
        cpu_type=cpu_type,
        cpu_subtype=cpu_subtype,
        is_64_bit=True,
        file_type="MH_EXECUTE" if file_type == MH_EXECUTE else "MH_DYLIB",
    )
    return record


def report_with_slices(*records: dict) -> dict:
    report = inspection_report()
    report["macho"]["slices"] = list(records)
    report["macho"]["slice_count"] = len(records)
    report["macho"]["architectures"] = sorted({record["arch"] for record in records})
    return report


def codes(result) -> set[str]:
    return {finding.code for finding in result.findings}


def test_authorized_owned_package_produces_dry_run_plan() -> None:
    result = evaluate(authorization_manifest(), inspection_report())
    assert result.preflight_passed is True
    assert result.plan is not None
    assert result.plan["mode"] == "dry_run"
    assert result.plan["execution_permitted"] is False
    assert result.plan["status"] == "READY_FOR_INDEPENDENT_REVIEW"
    assert result.plan["authorization"]["verification"] == "advisory_declaration_only"
    assert result.plan["authorization"]["cryptographically_verified"] is False
    assert result.plan["xinsta_core"]["install_name"] == "@rpath/libXinstaCore.dylib"
    assert result.plan["xinsta_core"]["hook"] is False
    assert result.plan["xinsta_core"]["swizzle"] is False
    blocked = {
        step["id"] for step in result.plan["steps"] if step["status"] == "blocked"
    }
    assert "check_owner_declaration" in {
        step["id"] for step in result.plan["steps"] if step["status"] == "passed"
    }
    assert "verify_owner_authorization" not in {
        step["id"] for step in result.plan["steps"]
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


def test_pinned_load_only_proof_produces_dry_run_plan() -> None:
    result = evaluate(load_only_manifest(), load_only_report())
    assert result.preflight_passed is True
    assert result.plan is not None
    assert result.plan["mode"] == "dry_run"
    assert result.plan["execution_permitted"] is False
    assert result.plan["purpose"] == "load_only_proof"
    assert result.plan["authorization"]["rights_basis"] == "load-only-proof"
    assert result.plan["xinsta_core"]["compatibility_adapter"] == IG456_ADAPTER
    assert result.plan["xinsta_core"]["hook"] is False
    assert result.plan["xinsta_core"]["swizzle"] is False

    blocked = {step["id"] for step in result.plan["steps"] if step["status"] == "blocked"}
    assert {
        "codesign_bundle_and_frameworks",
        "register_device_and_install",
        "verify_core_load_in_host",
        "verify_x_settings_in_host",
    } <= blocked
    assert any("permits no hook" in item for item in result.plan["limitations"])
    assert result.plan["package"]["sha256"] == IG456_SHA


@pytest.mark.parametrize(
    ("mutate_manifest", "expected_code"),
    [
        (
            lambda m: m["expected_identity"].update(version="456.0.1"),
            "BUNDLE_ID_NOT_ALLOWED",
        ),
        (
            lambda m: m["expected_identity"].update(build_number="1114925421"),
            "BUNDLE_ID_NOT_ALLOWED",
        ),
        (
            lambda m: m.update(rights_basis="owned-test-package"),
            "RIGHTS_BASIS_NOT_ALLOWED_FOR_LOAD_PROOF",
        ),
        (
            lambda m: m.update(expected_sha256="b" * 64),
            "SHA256_NOT_PINNED_FOR_LOAD_PROOF",
        ),
    ],
)
def test_load_only_proof_near_misses_are_rejected(mutate_manifest, expected_code) -> None:
    manifest = load_only_manifest()
    mutate_manifest(manifest)
    result = evaluate(manifest, load_only_report())
    assert result.preflight_passed is False
    assert expected_code in codes(result)
    assert result.plan is None


def test_load_only_proof_hash_is_pinned_even_when_report_matches() -> None:
    manifest = load_only_manifest()
    report = load_only_report()
    wrong_hash = "c" * 64
    manifest["expected_sha256"] = wrong_hash
    report["artifact"]["sha256"] = wrong_hash
    result = evaluate(manifest, report)
    assert result.preflight_passed is False
    assert "SHA256_NOT_PINNED_FOR_LOAD_PROOF" in codes(result)
    assert "SHA256_MISMATCH" not in codes(result)


def test_owned_test_package_cannot_use_load_only_rights_basis() -> None:
    manifest = authorization_manifest()
    manifest["rights_basis"] = "load-only-proof"
    result = evaluate(manifest, inspection_report())
    assert result.preflight_passed is False
    assert "RIGHTS_BASIS_NOT_ALLOWED_FOR_OWNED_TEST" in codes(result)


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


# --- B9-1: advisory declaration is not verified authorization ---------------


def test_plan_never_claims_verified_authorization() -> None:
    result = evaluate(authorization_manifest(), inspection_report())
    assert result.plan is not None
    assert result.plan["authorization"]["verification"] == "advisory_declaration_only"
    assert result.plan["authorization"]["cryptographically_verified"] is False
    output = json.dumps(result.to_dict()).lower()
    assert '"cryptographically_verified": true' not in output
    assert "verified authorization" not in output


# --- B9-4: bounded, output-safe identity strings ----------------------------


UNSAFE_VALUES = (
    "../secret",
    "a\\b",
    "demo.owned\x00x",
    "demo.owned\nSECRET",
    "demo.owned\u202e",
    "demo.owned\u200b",
    "A" * 257,
    "password=hunter2",
)


@pytest.mark.parametrize(
    ("side", "field"),
    [
        ("manifest", "authorization_id"),
        ("manifest", "bundle_id"),
        ("manifest", "expected_sha256"),
        ("report", "bundle_id"),
        ("report", "name"),
        ("report", "artifact_sha256"),
    ],
)
@pytest.mark.parametrize("bad", UNSAFE_VALUES)
def test_unsafe_identity_strings_are_rejected_without_echo(side, field, bad) -> None:
    manifest = authorization_manifest()
    report = inspection_report()
    if side == "manifest":
        if field == "bundle_id":
            manifest["expected_identity"]["bundle_id"] = bad
        else:
            manifest[field] = bad
    elif field == "artifact_sha256":
        report["artifact"]["sha256"] = bad
    else:
        report["identity"][field] = bad

    result = evaluate(manifest, report)
    assert UNSAFE_IDENTITY_CODE in codes(result)
    assert result.plan is None
    assert bad not in json.dumps(result.to_dict())


def test_third_party_bundle_with_unsafe_text_is_still_rejected() -> None:
    manifest = authorization_manifest()
    manifest["expected_identity"]["bundle_id"] = "com.burbn.instagram\u202e"
    result = evaluate(manifest, inspection_report())
    assert UNSAFE_IDENTITY_CODE in codes(result)
    assert "com.burbn.instagram" not in json.dumps(result.to_dict())


def test_report_context_and_secret_severity_are_never_echoed() -> None:
    report = inspection_report()
    report["findings"] = [
        {
            "code": "PATH_TRAVERSAL",
            "severity": "critical",
            "detail": "SUPER-SECRET-DETAIL",
            "context": {"password": "SECRET-VALUE"},
        }
    ]
    result = evaluate(authorization_manifest(), report)
    assert "CRITICAL_ANALYSIS_FINDING" in codes(result)
    output = json.dumps(result.to_dict())
    assert "SUPER-SECRET-DETAIL" not in output
    assert "SECRET-VALUE" not in output


# --- B9-5: architecture verification from real Mach-O header bytes ----------


@pytest.mark.parametrize(
    ("subtype", "expected_arch"),
    [(0, "arm64"), (1, "arm64"), (2, "arm64e")],
)
def test_real_macho_arm64_subtypes_are_accepted(subtype, expected_arch) -> None:
    record = slice_from_header(macho_header_bytes(CPU_TYPE_ARM64, subtype))
    assert record["arch"] == expected_arch
    result = evaluate(authorization_manifest(), report_with_slices(record))
    assert result.preflight_passed is True


def test_legacy_arm64v8_alias_is_normalised() -> None:
    record = slice_from_header(macho_header_bytes(CPU_TYPE_ARM64, 1))
    record["arch"] = "arm64v8"
    result = evaluate(authorization_manifest(), report_with_slices(record))
    assert result.preflight_passed is True


@pytest.mark.parametrize("arch", ["x86_64", "armv7", "mystery", 123, None])
def test_unsupported_architecture_strings_are_rejected(arch) -> None:
    record = slice_from_header(macho_header_bytes(CPU_TYPE_X86_64, 3))
    record["arch"] = arch
    result = evaluate(authorization_manifest(), report_with_slices(record))
    assert "MAIN_EXECUTABLE_ARCHITECTURE" in codes(result)
    assert result.preflight_passed is False


def test_real_x86_64_macho_header_is_rejected() -> None:
    record = slice_from_header(macho_header_bytes(CPU_TYPE_X86_64, 3))
    result = evaluate(authorization_manifest(), report_with_slices(record))
    assert "MAIN_EXECUTABLE_ARCHITECTURE" in codes(result)


def test_mixed_arm64_and_unsupported_slices_are_rejected() -> None:
    arm = slice_from_header(macho_header_bytes(CPU_TYPE_ARM64, 0))
    foreign = slice_from_header(macho_header_bytes(CPU_TYPE_X86_64, 3))
    result = evaluate(authorization_manifest(), report_with_slices(arm, foreign))
    assert "MAIN_EXECUTABLE_ARCHITECTURE" in codes(result)
    assert result.preflight_passed is False


# --- B9-6: recomputed finding severity --------------------------------------


def test_severity_map_covers_every_known_code() -> None:
    assert KNOWN_ANALYSIS_CODES == frozenset(EXPECTED_SEVERITIES)
    assert EXPECTED_SEVERITIES["WEAK_UNRESOLVED_RPATH_DEPENDENCY"] == "warning"
    assert EXPECTED_SEVERITIES["PROVISIONING_PROFILE_UNREADABLE"] == "warning"
    assert EXPECTED_SEVERITIES["ARCHIVE_CHANGED_DURING_ANALYSIS"] == "critical"
    assert EXPECTED_SEVERITIES["AMBIGUOUS_APPLICATION_ROOT"] == "critical"
    assert EXPECTED_SEVERITIES["INVALID_INFO_PLIST_VALUE"] == "critical"


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("WEAK_UNRESOLVED_RPATH_DEPENDENCY", "warning"),
        ("PROVISIONING_PROFILE_UNREADABLE", "warning"),
        ("ARCHIVE_CHANGED_DURING_ANALYSIS", "critical"),
        ("AMBIGUOUS_APPLICATION_ROOT", "critical"),
        ("INVALID_INFO_PLIST_VALUE", "critical"),
        ("PATH_TRAVERSAL", "critical"),
        ("DUPLICATE_ENTRY_NAME", "warning"),
        ("NO_EMBEDDED_EXTENSIONS", "info"),
    ],
)
def test_report_severity_is_recomputed_not_trusted(code, expected) -> None:
    wrong = "warning" if expected == "critical" else "critical"
    report = inspection_report()
    report["findings"] = [
        {
            "code": code,
            "severity": wrong,
            "detail": "SECRET-DETAIL",
            "context": {"token": "SECRET-CONTEXT"},
        }
    ]
    result = evaluate(authorization_manifest(), report)
    assert REPORT_INCONSISTENT_CODE in codes(result)
    assert result.plan is None
    output = json.dumps(result.to_dict())
    assert "SECRET-DETAIL" not in output
    assert "SECRET-CONTEXT" not in output


def test_expected_warning_code_becomes_a_review_item() -> None:
    report = inspection_report()
    report["findings"] = [
        {
            "code": "WEAK_UNRESOLVED_RPATH_DEPENDENCY",
            "severity": "warning",
            "detail": "x",
        }
    ]
    result = evaluate(authorization_manifest(), report)
    assert result.preflight_passed is True
    assert result.plan["review_findings"] == ["WEAK_UNRESOLVED_RPATH_DEPENDENCY"]


def test_expected_critical_code_blocks_the_plan() -> None:
    report = inspection_report()
    report["findings"] = [
        {
            "code": "ARCHIVE_CHANGED_DURING_ANALYSIS",
            "severity": "critical",
            "detail": "x",
        }
    ]
    result = evaluate(authorization_manifest(), report)
    assert "CRITICAL_ANALYSIS_FINDING" in codes(result)
    assert result.plan is None


# --- Report schema compatibility (1.0 and 1.1) ------------------------------


@pytest.mark.parametrize("version", sorted(ACCEPTED_REPORT_SCHEMA_VERSIONS))
def test_supported_report_schema_versions_are_accepted(version) -> None:
    report = inspection_report()
    report["schema_version"] = version
    assert evaluate(authorization_manifest(), report).preflight_passed is True


def test_unsupported_report_schema_is_rejected_without_echoing_it() -> None:
    secret_schema = "1.9-C:\\Users\\owner\\SECRET"
    report = inspection_report()
    report["schema_version"] = secret_schema
    result = evaluate(authorization_manifest(), report)
    assert "REPORT_INVALID" in codes(result)
    assert secret_schema not in json.dumps(result.to_dict())


@pytest.mark.parametrize(
    "value",
    [
        pytest.param([], id="list"),
        pytest.param({}, id="object"),
        pytest.param([1], id="list-with-value"),
        pytest.param({"marker": "SUPER_SECRET_SCHEMA"}, id="object-with-secret"),
    ],
)
def test_unhashable_report_schema_is_rejected_without_exception(value) -> None:
    report = inspection_report()
    report["schema_version"] = value

    result = evaluate(authorization_manifest(), report)

    assert "REPORT_INVALID" in codes(result)
    assert "SUPER_SECRET_SCHEMA" not in json.dumps(result.to_dict())


@pytest.mark.parametrize("value", [None, 1, True, 1.5])
def test_non_list_macho_slices_are_rejected_without_exception(value) -> None:
    report = inspection_report()
    report["macho"]["slices"] = value

    result = evaluate(authorization_manifest(), report)

    assert "REPORT_INVALID" in codes(result)
    assert result.plan is None


# --- B9-7: bounded JSON input in the CLI ------------------------------------


def _write_inputs(tmp_path, manifest_text: str, report: dict | None = None) -> list[str]:
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.json"
    manifest_path.write_text(manifest_text, encoding="utf-8")
    report_path.write_text(
        json.dumps(report if report is not None else inspection_report()), encoding="utf-8"
    )
    return ["--manifest", str(manifest_path), "--report", str(report_path)]


def test_cli_rejects_oversized_input(tmp_path, capsys) -> None:
    args = _write_inputs(tmp_path, "a" * (MAX_INPUT_BYTES + 1))
    assert main(args) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "input_too_large"}


def test_cli_rejects_excessive_json_depth(tmp_path, capsys) -> None:
    depth = MAX_JSON_DEPTH + 1
    payload = "[" * depth + "0" + "]" * depth
    args = _write_inputs(tmp_path, payload)
    assert main(args) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "json_too_deep"}


def test_cli_rejects_excessive_json_nodes(tmp_path, capsys) -> None:
    payload = "[" + ",".join(["0"] * (MAX_JSON_NODES + 1)) + "]"
    assert len(payload) < MAX_INPUT_BYTES
    args = _write_inputs(tmp_path, payload)
    assert main(args) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "json_too_many_nodes"}


def test_cli_recursion_safe_rejection(tmp_path, capsys) -> None:
    payload = "[" * 5000 + "0" + "]" * 5000
    args = _write_inputs(tmp_path, payload)
    assert main(args) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "json_too_deep"}


def test_cli_accepts_valid_report_schema_1_1(tmp_path, capsys) -> None:
    report = inspection_report()
    report["schema_version"] = "1.1"
    args = _write_inputs(tmp_path, json.dumps(authorization_manifest()), report)
    assert main(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["preflight_passed"] is True
    assert payload["plan"]["execution_permitted"] is False


def test_cli_rejects_oversized_integer_literal(tmp_path, capsys) -> None:
    args = _write_inputs(tmp_path, "9" * 5000)

    assert main(args) == 1
    assert json.loads(capsys.readouterr().out) == {"error": "input_unreadable"}


def test_documentation_states_the_current_review_and_schema_contract() -> None:
    document = Path(__file__).parents[1] / "docs" / "IPA_BUILD_MANAGER.md"
    text = document.read_text(encoding="utf-8")

    assert "has not been pushed" not in text
    assert 'pinned `schema_version = "1.0"`' not in text
    assert '44841872361' in text
    assert '44841879766' in text
    assert "`1.0`" in text
    assert "`1.1`" in text
