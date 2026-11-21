"""Build an unsigned private-pilot IPA from the pinned source inputs.

The CLI reports fixed error codes only and never echoes caller-supplied paths,
rights references, or underlying exception text. The output is not signed and
must be re-signed by an authorized signing workflow before installation.
"""
from __future__ import annotations

import argparse
import json

from project_x.packaging import PilotBuildError, build_unsigned_pilot_ipa


class InvalidArguments(Exception):
    """An argument error that must not echo user-controlled text."""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InvalidArguments(message)


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(
        prog="pilot_package_build",
        description="Build a distinct unsigned private-pilot IPA without signing or installing it.",
    )
    parser.add_argument("--ipa", required=True, help="path to the pinned source IPA")
    parser.add_argument("--dylib", required=True, help="path to the reviewed Core dylib")
    parser.add_argument("--output", required=True, help="path for the unsigned output IPA")
    parser.add_argument(
        "--rights-reference",
        required=True,
        help="non-secret private rights reference; never logged or embedded",
    )
    try:
        args = parser.parse_args(argv)
    except InvalidArguments:
        print(json.dumps({"error": "invalid_arguments"}, sort_keys=True))
        return 2

    try:
        result = build_unsigned_pilot_ipa(
            args.ipa,
            args.dylib,
            args.output,
            rights_reference=args.rights_reference,
        )
    except PilotBuildError as exc:
        print(json.dumps({"error": exc.code}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
