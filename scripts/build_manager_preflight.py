"""CLI for the read-only IPA build-manager preflight gate.

Usage (from the repository root):

    python -m scripts.build_manager_preflight \
        --manifest path/to/manifest.json \
        --report path/to/inspection-report.json

The command prints one JSON document to stdout. Exit codes: 0 = preflight
passed, 2 = preflight rejected, 1 = input could not be read or parsed. No file
is written and no external service or device is contacted.

Input documents are bounded before parsing: at most 4 MiB each, JSON depth 64
and 200,000 structural nodes. Only fixed error codes are emitted for input
errors; paths, decoder text and argument text are never echoed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from project_x.buildmanager import evaluate

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 200_000


class InvalidArguments(Exception):
    """An argument error that must not echo user-controlled argument text."""


class InputLimitError(Exception):
    """A bounded-input rejection whose ``code`` is safe to print."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser that never prints raw arguments or private paths."""

    def error(self, message: str) -> None:
        raise InvalidArguments(message)


def _load_bounded_json(path: Path) -> Any:
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise InputLimitError("input_too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InputLimitError("input_unreadable") from None

    # Iterative pre-scan so excessive nesting is rejected before the recursive
    # JSON decoder can raise RecursionError. Strings are skipped so braces and
    # commas inside values cannot distort the count.
    depth = 0
    nodes = 1
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            nodes += 1
            if depth > MAX_JSON_DEPTH:
                raise InputLimitError("json_too_deep")
        elif char in "}]":
            depth -= 1
        elif char in ",:":
            nodes += 1
        if nodes > MAX_JSON_NODES:
            raise InputLimitError("json_too_many_nodes")

    try:
        return json.loads(text)
    except RecursionError:
        raise InputLimitError("json_too_deep") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="unsigned owner declaration JSON")
    parser.add_argument("--report", required=True, type=Path, help="IPA inspection report JSON")
    try:
        args = parser.parse_args(argv)
    except InvalidArguments:
        print(json.dumps({"error": "invalid_arguments"}))
        return 1

    try:
        manifest_payload = _load_bounded_json(args.manifest)
        report_payload = _load_bounded_json(args.report)
    except InputLimitError as exc:
        print(json.dumps({"error": exc.code}))
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        # Do not echo paths or decoder detail: inputs may live in a private folder.
        print(json.dumps({"error": "input_unreadable", "kind": type(exc).__name__}))
        return 1

    result = evaluate(manifest_payload, report_payload)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.preflight_passed else 2


if __name__ == "__main__":
    sys.exit(main())
