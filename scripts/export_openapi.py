"""Reproducible, reviewed OpenAPI spec; no server or database connection needed."""
import argparse
import json
from pathlib import Path
from project_x.server.api import create_app
from project_x.server.config import Settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if checked-in OpenAPI is stale")
    args = parser.parse_args()
    app = create_app(Settings(database_url="sqlite:///./docs-only.db", code_pepper="X" * 40,
                              token_pepper="Y" * 40))
    content = json.dumps(app.openapi(), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    target = Path(__file__).resolve().parents[1] / "docs" / "openapi.json"
    if args.check:
        if not target.exists() or target.read_text() != content:
            raise SystemExit("OpenAPI documentation is outdated; run python -m scripts.export_openapi")
        print("OpenAPI schema matches implementation")
    else:
        target.write_text(content)
        print("Wrote", target)
    app.state.engine.dispose()


if __name__ == "__main__":
    main()
