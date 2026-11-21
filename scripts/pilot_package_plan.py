"""Print a deterministic dry-run private-pilot packaging plan as JSON.

The CLI reports fixed error codes only. It never prints caller-supplied paths or
underlying exception text.
"""
from __future__ import annotations

import argparse
import json
import sys

from project_x.packaging import PilotPlanError, build_pilot_package_plan, plan_json


class InvalidArguments(Exception):
    """An argument error that must not echo user-controlled text."""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InvalidArguments(message)


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(
        prog="pilot_package_plan",
        description="Describe private-pilot packaging changes without executing them.",
    )
    parser.add_argument("--ipa", required=True, help="path to the pinned source IPA")
    parser.add_argument("--dylib", required=True, help="path to the unsigned Core dylib")
    try:
        args = parser.parse_args(argv)
    except InvalidArguments:
        print(json.dumps({"error": "invalid_arguments"}, sort_keys=True))
        return 2

    try:
        plan = build_pilot_package_plan(args.ipa, args.dylib)
    except PilotPlanError as exc:
        print(json.dumps({"error": exc.code}, sort_keys=True))
        return 2
    print(plan_json(plan), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
