#!/usr/bin/env python3
"""Leak-check case files that the model sees.

Run from the repo root:
    uv run python scripts/leak_check.py cases/SSB-0001
    uv run python scripts/leak_check.py --all

Scans the vulnerable sources and prompt.md for words that reveal the bug
(the bug class, remediation words, and the case's leak_terms field).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness"))

import leak_check  # noqa: E402
from common import Case, load_cases  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case", type=Path, nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--cases", type=Path, default=Path("cases"))
    args = ap.parse_args()
    if args.all:
        cases = load_cases(args.cases)
    elif args.case:
        c = args.case.resolve()
        cases = [Case(c, yaml.safe_load((c / "meta.yaml").read_text()) or {})]
    else:
        ap.error("need a case path or --all")
    leaked_cases = 0
    for c in cases:
        findings = leak_check.scan_case(c)
        if findings:
            leaked_cases += 1
            print(f"{c.id}: {len(findings)} leak(s)")
            for rel, line, term, snippet in findings[:20]:
                print(f"  {rel}:{line} '{term}': {snippet}")
        else:
            print(f"{c.id}: clean")
    return 1 if leaked_cases else 0


if __name__ == "__main__":
    sys.exit(main())
