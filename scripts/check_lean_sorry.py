#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable


SORRY_PATTERN = re.compile(r"\bsorry\b")


def iter_lean_files(root: Path, exclude_dirs: set[str]) -> Iterable[Path]:
    for path in sorted(root.rglob("*.lean")):
        if any(part in exclude_dirs for part in path.parts):
            continue
        yield path


def strip_comments_and_strings(text: str) -> str:
    result: list[str] = []
    index = 0
    length = len(text)
    block_depth = 0
    in_string = False

    while index < length:
        ch = text[index]
        nxt = text[index + 1] if index + 1 < length else ""

        if in_string:
            if ch == '\\' and index + 1 < length:
                result.append(' ')
                result.append(' ' if text[index + 1] != '\n' else '\n')
                index += 2
                continue
            if ch == '"':
                in_string = False
                result.append(' ')
            else:
                result.append('\n' if ch == '\n' else ' ')
            index += 1
            continue

        if block_depth > 0:
            if ch == '/' and nxt == '-':
                block_depth += 1
                result.extend([' ', ' '])
                index += 2
                continue
            if ch == '-' and nxt == '/':
                block_depth -= 1
                result.extend([' ', ' '])
                index += 2
                continue
            result.append('\n' if ch == '\n' else ' ')
            index += 1
            continue

        if ch == '-' and nxt == '-':
            result.extend([' ', ' '])
            index += 2
            while index < length and text[index] != '\n':
                result.append(' ')
                index += 1
            continue

        if ch == '/' and nxt == '-':
            block_depth = 1
            result.extend([' ', ' '])
            index += 2
            continue

        if ch == '"':
            in_string = True
            result.append(' ')
            index += 1
            continue

        result.append(ch)
        index += 1

    return ''.join(result)


def find_sorry_lines(path: Path) -> list[int]:
    stripped = strip_comments_and_strings(path.read_text(encoding="utf-8"))
    matches: list[int] = []
    for line_number, line in enumerate(stripped.splitlines(), start=1):
        if SORRY_PATTERN.search(line):
            matches.append(line_number)
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail if Lean source files contain real sorry tokens outside strings/comments."
    )
    parser.add_argument("root", type=Path, help="Lean project root to scan")
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to exclude from the recursive scan",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    exclude_dirs = set(args.exclude_dir)
    failures: list[str] = []

    for path in iter_lean_files(root, exclude_dirs):
        relative = path.relative_to(root)
        for line_number in find_sorry_lines(path):
            failures.append(f"{relative}:{line_number}")

    if failures:
        print("Found Lean sorry tokens:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"No Lean sorry tokens found under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())