"""CLI for the read-only IPA build-manager preflight gate.

Usage (from the repository root):

    python -m scripts.build_manager_preflight \
        --manifest path/to/manifest.json \
        --report path/to/inspection-report.json

The command prints one JSON document to stdout. Exit codes: 0 = preflight
passed, 2 = preflight rejected, 1 = input could not be read or parsed. No file
is written and no external service or device is contacted.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from project_x.buildmanager import evaluate


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="owner authorization JSON")
    parser.add_argument("--report", required=True, type=Path, help="IPA inspection report JSON")
    args = parser.parse_args(argv)

    try:
        manifest_payload = json.loads(args.manifest.read_text(encoding="utf-8"))
        report_payload = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        # Do not echo paths or decoder detail: inputs may live in a private folder.
        print(json.dumps({"error": "input_unreadable", "kind": type(exc).__name__}))
        return 1

    result = evaluate(manifest_payload, report_payload)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.preflight_passed else 2


if __name__ == "__main__":
    sys.exit(main())
