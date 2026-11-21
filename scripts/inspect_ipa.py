"""Read-only IPA inspection CLI.

The archive is opened, read under hard limits and closed. Nothing is extracted,
repackaged or modified, and the reference file is never written to.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from project_x.ipa import (
    AmbiguousAppRootError,
    ArchiveLimits,
    ArchiveSafetyError,
    MalformedInfoPlistError,
    inspect_ipa,
)
from project_x.ipa.bundle import BundleError


def _limits_from_args(args) -> ArchiveLimits | None:
    overrides = {}
    if args.max_total_bytes is not None:
        overrides["max_total_uncompressed_bytes"] = args.max_total_bytes
    if args.max_entries is not None:
        overrides["max_entries"] = args.max_entries
    return ArchiveLimits(**overrides) if overrides else None


class OutputCollisionError(Exception):
    """The output target became the input archive before publication."""


class OutputPublishError(Exception):
    """The report could not be published without overwriting an existing target."""


def _path_identity(path: str) -> tuple[int, int] | None:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return (stat.st_dev, stat.st_ino)


def _output_collides(
    input_path: str,
    output_path: str,
    input_identity: tuple[int, int] | None = None,
) -> bool:
    """True when writing ``output_path`` could overwrite the input archive."""
    source_identity = input_identity or _path_identity(input_path)
    target_identity = _path_identity(output_path)
    try:
        if Path(input_path).resolve() == Path(output_path).resolve():
            return True
    except OSError:
        pass
    if source_identity is not None and source_identity == target_identity:
        return True
    try:
        return os.path.samefile(input_path, output_path)
    except OSError:
        return False


def _write_report(
    output_path: str,
    payload: str,
    *,
    input_path: str,
    input_identity: tuple[int, int] | None,
) -> None:
    """Publish a report without following symlinks or overwriting the archive.

    A temporary file is created in the destination directory. The target is
    removed only after two collision checks, then the temporary file is
    published with a no-overwrite hard link. If a concurrent rename places the
    input archive at the target after the final check, the link fails and the
    archive is left untouched instead of being replaced by report bytes.
    """
    if _output_collides(input_path, output_path, input_identity):
        raise OutputCollisionError
    target = Path(output_path)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".inspect-ipa-", dir=str(target.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload + "\n")
        if _output_collides(input_path, output_path, input_identity):
            raise OutputCollisionError
        try:
            if target.exists() or target.is_symlink():
                target.unlink()
        except OSError as exc:
            raise OutputPublishError from exc
        try:
            os.link(temporary, target)
        except FileExistsError as exc:
            # A concurrent rename recreated the target after the final check.
            # Never replace it: it may be the input archive.
            if _output_collides(input_path, output_path, input_identity):
                raise OutputCollisionError from exc
            raise OutputPublishError from exc
        except OSError as exc:
            raise OutputPublishError from exc
    finally:
        if temporary.exists():
            temporary.unlink()


def _summary(report) -> str:
    data = report.to_dict()
    identity = data["identity"]
    lines = [
        f"file        : {data['artifact']['file_name']}",
        f"size        : {data['artifact']['size_bytes']} bytes",
        f"sha256      : {data['artifact']['sha256'] or 'not computed'}",
        f"bundle id   : {identity['bundle_id']}",
        f"version     : {identity['version']} ({identity['build_number']})",
        f"minimum os  : {identity['minimum_os']}",
        f"architectures: {', '.join(data['macho']['architectures']) or 'unknown'}",
        f"encryption  : {', '.join(str(s['encryption']['cryptid']) for s in data['macho']['slices']) or 'unknown'}",
        f"entries     : {data['artifact']['entry_count']}",
        "bundles     : "
        + ", ".join(f"{k}={v}" for k, v in data["bundles"]["counts"].items()),
        f"protected   : {', '.join(data['dependencies']['protected_frameworks']) or 'none'}",
    ]
    severities: dict[str, int] = {}
    for finding in data["findings"]:
        severities[finding["severity"]] = severities.get(finding["severity"], 0) + 1
    lines.append(
        "findings    : "
        + (", ".join(f"{k}={v}" for k, v in sorted(severities.items())) or "none")
    )
    for finding in data["findings"]:
        if finding["severity"] in ("critical", "warning"):
            lines.append(f"  [{finding['severity']}] {finding['code']}: {finding['detail']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inspect_ipa",
        description="Statically inspect an .ipa without extracting or modifying it.",
    )
    parser.add_argument("ipa", help="path to the .ipa file")
    parser.add_argument("--json", dest="json_out", help="write the full report to this path")
    parser.add_argument("--summary", action="store_true", help="print a short summary instead of JSON")
    parser.add_argument("--no-hash", action="store_true", help="skip SHA-256 (faster on large archives)")
    parser.add_argument("--max-total-bytes", type=int, default=None, help="override the uncompressed size ceiling")
    parser.add_argument("--max-entries", type=int, default=None, help="override the entry count ceiling")
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="exit with status 1 when any critical finding is present",
    )
    args = parser.parse_args(argv)

    input_identity = _path_identity(args.ipa)
    if args.json_out and _output_collides(args.ipa, args.json_out, input_identity):
        print(
            "REFUSED [OUTPUT_COLLIDES_WITH_INPUT] the report path is the input archive",
            file=sys.stderr,
        )
        return 2

    try:
        report = inspect_ipa(
            args.ipa,
            limits=_limits_from_args(args),
            compute_sha256=not args.no_hash,
        )
    except ArchiveSafetyError as exc:
        print(f"REFUSED [{exc.code}] {exc.detail}", file=sys.stderr)
        return 2
    except AmbiguousAppRootError as exc:
        print(f"REFUSED [AMBIGUOUS_APPLICATION_ROOT] {exc}", file=sys.stderr)
        return 2
    except MalformedInfoPlistError as exc:
        print(f"REFUSED [INVALID_INFO_PLIST_VALUE] {exc}", file=sys.stderr)
        return 2
    except BundleError as exc:
        print(f"REFUSED [NOT_AN_APPLICATION_IPA] {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"REFUSED [FILE_NOT_FOUND] {args.ipa}", file=sys.stderr)
        return 2

    payload = report.to_json()
    if args.json_out:
        try:
            _write_report(
                args.json_out,
                payload,
                input_path=args.ipa,
                input_identity=input_identity,
            )
        except OutputCollisionError:
            print(
                "REFUSED [OUTPUT_COLLIDES_WITH_INPUT] the report target became the input archive",
                file=sys.stderr,
            )
            return 2
        except OutputPublishError:
            print(
                "REFUSED [OUTPUT_WRITE_FAILED] the report could not be published safely",
                file=sys.stderr,
            )
            return 2

    print(_summary(report) if args.summary else payload)

    if args.fail_on_critical:
        critical = [f for f in report.findings if f.severity == "critical"]
        if critical:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
