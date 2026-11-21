"""Report-to-plan contract tests using real analyzer output.

The analysis engine inspects a synthetic, locally generated owned IPA; its
versioned JSON report is then fed to the approved read-only preflight gate.
No third-party IPA, credential, signing identity, device or network access is
used. The plan remains a dry-run document with ``execution_permitted = false``.
"""
from __future__ import annotations

import copy
import json
import plistlib
from pathlib import Path

import pytest

from project_x.buildmanager import evaluate
from project_x.buildmanager.preflight import KNOWN_ANALYSIS_CODES
from project_x.ipa import AmbiguousAppRootError, inspect_ipa
from scripts.build_manager_preflight import main as preflight_cli
from tests.ipa_fixtures import (
    APP,
    CPU_X86_64,
    LC_LOAD_DYLIB,
    base_entries,
    build_macho,
    owned_info,
    write_ipa,
)

AUTH_ID = "AUTH-INTEGRATION-001"
TIMESTAMP = "2026-11-21T00:00:00Z"


def owned_ipa(
    tmp_path: Path,
    *,
    name: str = "OwnedDemo.ipa",
    info: dict | None = None,
    executable: bytes | None = None,
    entries: dict[str, bytes] | None = None,
) -> Path:
    payload = entries or base_entries(
        info=info or owned_info(),
        executable=executable if executable is not None else build_macho(cryptid=0),
    )
    return write_ipa(tmp_path / name, payload)


def analyzer_report(path: Path) -> dict:
    return inspect_ipa(path, generated_at=TIMESTAMP).to_dict()


def manifest_for(report: dict) -> dict:
    identity = report["identity"]
    return {
        "schema_version": "1.0",
        "owner_authorized": True,
        "authorization_id": AUTH_ID,
        "expected_identity": {
            "bundle_id": identity["bundle_id"],
            "version": identity["version"],
            "build_number": identity["build_number"],
        },
        "expected_sha256": report["artifact"]["sha256"],
        "rights_basis": "owned-test-package",
    }


def codes(report: dict) -> set[str]:
    return {item["code"] for item in report["findings"]}


def test_real_analyzer_report_feeds_approved_preflight(tmp_path: Path) -> None:
    path = owned_ipa(tmp_path)
    report = analyzer_report(path)
    result = evaluate(manifest_for(report), report)

    assert result.preflight_passed is True
    assert result.plan is not None
    assert result.plan["mode"] == "dry_run"
    assert result.plan["execution_permitted"] is False
    assert result.plan["status"] == "READY_FOR_INDEPENDENT_REVIEW"
    assert result.plan["package"] == {
        "bundle_id": "demo.owned",
        "version": "1.0.0",
        "build_number": "7",
        "sha256": report["artifact"]["sha256"],
    }
    assert result.plan["authorization"] == {
        "authorization_id": AUTH_ID,
        "rights_basis": "owned-test-package",
        "verification": "advisory_declaration_only",
        "cryptographically_verified": False,
    }
    assert "NO_EMBEDDED_EXTENSIONS" in codes(report)
    assert result.plan["review_findings"] == []
    blocked = {step["id"] for step in result.plan["steps"] if step["status"] == "blocked"}
    assert {
        "codesign_bundle_and_frameworks",
        "register_device_and_install",
        "verify_x_settings_in_host",
    } <= blocked
    assert all(credential["provided"] is False for credential in result.plan["required_credentials"])


def test_all_codes_from_real_reports_are_in_the_preflight_allowlist(tmp_path: Path) -> None:
    entries = base_entries(info=owned_info(), executable=build_macho(cryptid=0))
    missing_executable = dict(entries)
    missing_executable.pop(APP + "Demo")

    unresolved = base_entries(
        info=owned_info(),
        executable=build_macho(
            cryptid=0, dylibs=(("@rpath/Missing.framework/Missing", LC_LOAD_DYLIB),)
        ),
    )

    scenarios = {
        "clean": owned_ipa(tmp_path, name="Clean.ipa", entries=entries),
        "encrypted": owned_ipa(
            tmp_path,
            name="Encrypted.ipa",
            entries=base_entries(info=owned_info(), executable=build_macho(cryptid=1)),
        ),
        "missing_executable": owned_ipa(
            tmp_path, name="Missing.ipa", entries=missing_executable
        ),
        "unresolved_rpath": owned_ipa(
            tmp_path, name="Unresolved.ipa", entries=unresolved
        ),
    }

    observed: set[str] = set()
    for label, path in scenarios.items():
        report = analyzer_report(path)
        emitted = codes(report)
        assert emitted, f"{label} produced no analyzer findings"
        assert emitted <= KNOWN_ANALYSIS_CODES, f"{label}: {emitted - KNOWN_ANALYSIS_CODES}"
        observed |= emitted

    assert "MAIN_BINARY_DECRYPTED" in observed
    assert "MAIN_BINARY_ENCRYPTED" in observed
    assert "EXECUTABLE_NOT_PRESENT" in observed
    assert "UNRESOLVED_RPATH_DEPENDENCY" in observed


def test_real_critical_finding_blocks_the_plan(tmp_path: Path) -> None:
    entries = base_entries(info=owned_info(), executable=build_macho(cryptid=0))
    entries.pop(APP + "Demo")
    path = owned_ipa(tmp_path, name="MissingExecutable.ipa", entries=entries)
    report = analyzer_report(path)

    result = evaluate(manifest_for(report), report)

    assert result.preflight_passed is False
    assert result.plan is None
    found = {item.code for item in result.findings}
    assert "CRITICAL_ANALYSIS_FINDING" in found
    assert "MAIN_EXECUTABLE_SLICES_MISSING" in found


def test_hash_binding_uses_the_real_artifact_hash(tmp_path: Path) -> None:
    first = owned_ipa(tmp_path, name="First.ipa")
    second = owned_ipa(
        tmp_path,
        name="Second.ipa",
        executable=build_macho(cryptid=0, rpaths=("@executable_path/Frameworks",)),
    )
    first_report = analyzer_report(first)
    second_report = analyzer_report(second)
    assert first_report["artifact"]["sha256"] != second_report["artifact"]["sha256"]

    stale_result = evaluate(manifest_for(first_report), second_report)
    assert stale_result.preflight_passed is False
    assert "SHA256_MISMATCH" in {item.code for item in stale_result.findings}

    current_result = evaluate(manifest_for(second_report), second_report)
    assert current_result.preflight_passed is True


def test_unowned_identity_from_real_report_is_rejected(tmp_path: Path) -> None:
    info = owned_info()
    info["CFBundleIdentifier"] = "demo.unowned"  # fictional, not a real product
    report = analyzer_report(owned_ipa(tmp_path, name="Unowned.ipa", info=info))

    result = evaluate(manifest_for(report), report)

    assert result.preflight_passed is False
    assert result.plan is None
    assert "BUNDLE_ID_NOT_ALLOWED" in {item.code for item in result.findings}


def test_real_warning_is_retained_without_leaking_archive_paths(tmp_path: Path) -> None:
    entries = base_entries(info=owned_info(), executable=build_macho(cryptid=0))
    entries[APP + "PlugIns/Widget.appex/Info.plist"] = plistlib.dumps(
        {
            "CFBundleIdentifier": "demo.owned.widget",
            "CFBundleName": "Widget",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "7",
            "MinimumOSVersion": "16.3",
            "CFBundleExecutable": "Widget",
        },
        fmt=plistlib.FMT_BINARY,
    )
    entries[APP + "PlugIns/Widget.appex/Widget"] = build_macho()
    report = analyzer_report(owned_ipa(tmp_path, name="Widget.ipa", entries=entries))

    result = evaluate(manifest_for(report), report)

    assert result.preflight_passed is True
    assert result.plan is not None
    assert "UNSIGNED_NESTED_BUNDLE" in codes(report)
    assert result.plan["review_findings"] == ["UNSIGNED_NESTED_BUNDLE"]
    serialised = json.dumps(result.to_dict())
    assert "Payload/" not in serialised
    assert str(tmp_path) not in serialised


def test_cli_accepts_a_real_analyzer_report_without_echoing_private_paths(
    tmp_path: Path, capsys
) -> None:
    private_dir = tmp_path / "private-family-photos"
    private_dir.mkdir()
    ipa = owned_ipa(private_dir, name="OwnedDemo.ipa")
    report_path = private_dir / "report.json"
    manifest_path = private_dir / "manifest.json"
    report = analyzer_report(ipa)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest_for(report)), encoding="utf-8")

    exit_code = preflight_cli(
        ["--manifest", str(manifest_path), "--report", str(report_path)]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert payload["preflight_passed"] is True
    assert payload["plan"]["package"]["sha256"] == report["artifact"]["sha256"]
    assert "private-family-photos" not in captured.out + captured.err


def test_current_and_legacy_report_schemas_are_accepted(tmp_path: Path) -> None:
    report = analyzer_report(owned_ipa(tmp_path, name="Schema.ipa"))
    assert report["schema_version"] == "1.1"
    assert evaluate(manifest_for(report), report).preflight_passed is True

    legacy = copy.deepcopy(report)
    legacy["schema_version"] = "1.0"
    assert evaluate(manifest_for(legacy), legacy).preflight_passed is True

    future = copy.deepcopy(report)
    future["schema_version"] = "9.9"
    rejected = evaluate(manifest_for(future), future)
    assert rejected.preflight_passed is False
    assert "REPORT_INVALID" in {item.code for item in rejected.findings}
    assert "9.9" not in json.dumps(rejected.to_dict())


def test_modified_archive_bytes_break_the_exact_hash_binding(tmp_path: Path) -> None:
    path = owned_ipa(tmp_path, name="Modified.ipa")
    original_report = analyzer_report(path)
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    comment_length = int.from_bytes(data[eocd + 20 : eocd + 22], "little")
    extra = b"appended-after-inspection"
    data.extend(extra)
    data[eocd + 20 : eocd + 22] = (comment_length + len(extra)).to_bytes(2, "little")
    path.write_bytes(data)
    modified_report = analyzer_report(path)

    assert modified_report["artifact"]["sha256"] != original_report["artifact"]["sha256"]
    rejected = evaluate(manifest_for(original_report), modified_report)
    assert rejected.preflight_passed is False
    assert "SHA256_MISMATCH" in {item.code for item in rejected.findings}


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        pytest.param(lambda m: m.update(owner_authorized=False), "MANIFEST_INVALID", id="not-authorized"),
        pytest.param(lambda m: m.update(expected_sha256="0" * 64), "SHA256_MISMATCH", id="forged-hash"),
        pytest.param(
            lambda m: m["expected_identity"].update(version="9.9.9"),
            "VERSION_MISMATCH",
            id="wrong-version",
        ),
        pytest.param(
            lambda m: m.update(rights_basis="asserted-by-caller"),
            "MANIFEST_INVALID",
            id="unknown-rights-basis",
        ),
        pytest.param(
            lambda m: m.update(unexpected_field="SUPER-SECRET-TOKEN-123"),
            "MANIFEST_INVALID",
            id="unexpected-field",
        ),
    ],
)
def test_forged_or_unexpected_authorization_is_rejected_without_echo(
    tmp_path: Path, mutate, expected: str
) -> None:
    report = analyzer_report(owned_ipa(tmp_path, name="ForgedAuth.ipa"))
    manifest = manifest_for(report)
    mutate(manifest)

    result = evaluate(manifest, report)

    assert result.preflight_passed is False
    assert result.plan is None
    assert expected in {item.code for item in result.findings}
    serialised = json.dumps(result.to_dict())
    assert "SUPER-SECRET-TOKEN-123" not in serialised


def test_unsafe_authorization_identifier_is_rejected_without_echo(tmp_path: Path) -> None:
    report = analyzer_report(owned_ipa(tmp_path, name="UnsafeAuth.ipa"))
    manifest = manifest_for(report)
    leak = "SUPER-SECRET-TOKEN-123"
    manifest["authorization_id"] = leak

    result = evaluate(manifest, report)

    assert result.preflight_passed is False
    assert "UNSAFE_IDENTITY_STRING" in {item.code for item in result.findings}
    assert leak not in json.dumps(result.to_dict())


def test_malformed_real_report_is_rejected_without_echoing_values(tmp_path: Path) -> None:
    report = analyzer_report(owned_ipa(tmp_path, name="MalformedReport.ipa"))

    unknown_code = copy.deepcopy(report)
    unknown_code["findings"] = [{"code": "SUPER_SECRET_FINDING", "severity": "critical"}]
    rejected_code = evaluate(manifest_for(unknown_code), unknown_code)
    assert rejected_code.preflight_passed is False
    assert "REPORT_INVALID" in {item.code for item in rejected_code.findings}
    assert "SUPER_SECRET_FINDING" not in json.dumps(rejected_code.to_dict())

    inconsistent = copy.deepcopy(report)
    first = inconsistent["findings"][0]
    first["severity"] = "critical" if first["severity"] != "critical" else "info"
    rejected_severity = evaluate(manifest_for(inconsistent), inconsistent)
    assert rejected_severity.preflight_passed is False
    assert "REPORT_INCONSISTENT" in {item.code for item in rejected_severity.findings}


def test_ambiguous_archive_is_refused_before_any_planning(tmp_path: Path) -> None:
    entries = base_entries(info=owned_info(), executable=build_macho(cryptid=0))
    entries["Payload/Second.app/README.txt"] = b"another application root"
    path = write_ipa(tmp_path / "Ambiguous.ipa", entries)

    with pytest.raises(AmbiguousAppRootError):
        analyzer_report(path)


def test_unsupported_architecture_from_real_report_blocks_the_plan(tmp_path: Path) -> None:
    entries = base_entries(
        info=owned_info(), executable=build_macho(cryptid=0, cpu_type=CPU_X86_64)
    )
    report = analyzer_report(owned_ipa(tmp_path, name="X86.ipa", entries=entries))
    assert "NON_ARM64_ARCHITECTURE" in codes(report)

    result = evaluate(manifest_for(report), report)

    assert result.preflight_passed is False
    assert result.plan is None
    assert "MAIN_EXECUTABLE_ARCHITECTURE" in {item.code for item in result.findings}
