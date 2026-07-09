"""Emit ``rules_catalog.json`` (ko + en) for bundling into the native macOS app.

The web dashboard reads the catalog live from ``GET /api/rules``; macOS has no
Python at runtime, so it ships a generated copy of the same catalog as an app
resource. Run as a build step:

    python -m security_scanner.rules_export path/to/rules_catalog.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .reporting import build_rule_catalog


def build_catalog_document() -> dict[str, object]:
    return {language: build_rule_catalog(language) for language in ("ko", "en")}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    output = Path(args[0]) if args else Path("rules_catalog.json")
    output.write_text(json.dumps(build_catalog_document(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote rule catalog to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
