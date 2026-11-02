"""Validate one case: metadata, builds, test rules, and leak check.

Run from the repo root:
    uv run python harness/check_case.py cases/SSB-0001
    uv run python harness/check_case.py --all

Checks:
- meta.yaml has all required fields; reviewers accepts [self] before v1.0.
- Functional tests pass on both vulnerable/ and fixed/.
- The exploit test passes on vulnerable/ and fails on fixed/. When tests/exploit/
  has no test yet, the check is skipped and reported as an owner task, not an error.
- No leak terms in any file the model sees (sources and prompt).
- Warns when the installed Sui CLI differs from meta sui_version.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml
from common import Case, load_cases, run_move_tests
from leak_check import scan_case

REQUIRED = [
    "id",
    "title",
    "source",
    "reference",
    "report_date",
    "severity",
    "bug_class",
    "bug_location",
    "contamination_risk",
    "tasks",
    "sui_version",
    "license_note",
    "reviewers",
    "added",
]


def installed_sui_version() -> str | None:
    try:
        out = subprocess.run(["sui", "--version"], capture_output=True, text=True, timeout=30)
        m = re.search(r"(\d+\.\d+\.\d+)", out.stdout)
        return m.group(1) if m else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def check_case(case: Case) -> list[str]:
    errors: list[str] = []
    meta = case.meta
    for k in REQUIRED:
        if not meta.get(k):
            errors.append(f"missing field: {k}")
    reviewers = meta.get("reviewers") or []
    if not reviewers:
        errors.append("needs at least one reviewer ([self] is allowed before v1.0)")
    elif "self" not in reviewers and len(reviewers) < 2:
        errors.append("needs a second reviewer before v1.0")
    if meta.get("bug_class") == "none" and meta.get("source") != "clean":
        errors.append("bug_class none requires source clean")

    func = case.path / "tests" / "functional"
    expl = case.path / "tests" / "exploit"
    checks = [
        ("functional on vulnerable", case.path / "vulnerable", [func], True),
        ("functional on fixed", case.path / "fixed", [func], True),
    ]
    if meta.get("source") == "clean":
        if list(expl.glob("*.move")):
            errors.append("clean case should not have an exploit test")
    elif not list(expl.glob("*.move")):
        if "exploit" in meta.get("tasks", []):
            print("[SKIP] exploit test missing (owner task)")
    else:
        checks += [
            ("exploit on vulnerable (must pass)", case.path / "vulnerable", [expl], True),
            ("exploit on fixed (must fail)", case.path / "fixed", [expl], False),
        ]
    for name, pkg, dirs, want in checks:
        res = run_move_tests(pkg, dirs)
        status = "OK" if res.passed == want else "FAIL"
        print(f"[{status}] {name} (phase={res.phase})")
        if res.passed != want:
            errors.append(f"{name} phase={res.phase}\n{res.log[-2000:]}")

    for rel, line, term, snippet in scan_case(case):
        errors.append(f"leak: {rel}:{line} '{term}': {snippet}")

    v = installed_sui_version()
    if v and meta.get("sui_version") and v != str(meta["sui_version"]):
        print(f"[WARN] installed sui {v} != meta sui_version {meta['sui_version']}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case", type=Path, nargs="?", help="case folder")
    ap.add_argument("--all", action="store_true", help="check every case in --cases")
    ap.add_argument("--cases", type=Path, default=Path("cases"))
    args = ap.parse_args()
    if args.all:
        cases = [c for c in load_cases(args.cases)]
    elif args.case:
        c = args.case.resolve()
        cases = [Case(c, yaml.safe_load((c / "meta.yaml").read_text()) or {})]
    else:
        ap.error("need a case path or --all")
    failed = 0
    for c in cases:
        errors = check_case(c)
        if errors:
            failed += 1
            print(f"== {c.id} FAIL")
            for e in errors:
                print("ERROR:", e)
        else:
            print(f"== {c.id} PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
