#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


TEST_METHOD_RE = re.compile(r"^(?P<indent>\s*)method\s+Test[A-Za-z0-9_]*\s*\(")


def strip_test_methods(content: str) -> str:
    lines = content.splitlines(keepends=True)
    output: list[str] = []
    skipping = False
    brace_depth = 0

    for line in lines:
        if not skipping:
            if TEST_METHOD_RE.match(line):
                skipping = True
                brace_depth = line.count("{") - line.count("}")
                continue
            output.append(line)
            continue

        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0:
            skipping = False
            brace_depth = 0

    return "".join(output)


def process_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(strip_test_methods(source.read_text()), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Copy Dafny sources while stripping top-level Test* methods used as example harnesses."
    )
    parser.add_argument("source_root", type=Path)
    parser.add_argument("destination_root", type=Path)
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    destination_root = args.destination_root.resolve()

    for source in source_root.rglob("*.dfy"):
        relative = source.relative_to(source_root)
        process_file(source, destination_root / relative)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())