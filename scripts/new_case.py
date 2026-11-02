#!/usr/bin/env python3
"""Create the next case from cases/_template.

Run from the repo root:
    uv run python scripts/new_case.py

Copies _template to the next free SSB-#### id, fills in id, added, and
sui_version, and resets the free-text fields.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "cases"


def installed_sui_version() -> str:
    try:
        out = subprocess.run(["sui", "--version"], capture_output=True, text=True, timeout=30)
        m = re.search(r"(\d+\.\d+\.\d+)", out.stdout)
        if m:
            return m.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def next_id() -> str:
    highest = 0
    if CASES.exists():
        for d in CASES.iterdir():
            m = re.match(r"SSB-(\d{4})$", d.name)
            if d.is_dir() and m:
                highest = max(highest, int(m.group(1)))
    return f"SSB-{highest + 1:04d}"


def main() -> None:
    new_id = next_id()
    src = CASES / "_template"
    dest = CASES / new_id
    if dest.exists():
        sys.exit(f"{dest} already exists")
    shutil.copytree(src, dest)
    meta_path = dest / "meta.yaml"
    meta = yaml.safe_load(meta_path.read_text())
    meta["id"] = new_id
    meta["added"] = date.today().isoformat()
    meta["sui_version"] = installed_sui_version()
    for k in ("title", "reference", "auditor", "bug_class", "bug_location", "report_date", "license_note"):
        meta[k] = ""
    meta["reviewers"] = []
    meta_path.write_text(yaml.safe_dump(meta, sort_keys=False, allow_unicode=True))
    print(f"created {dest}")
    print("next: fill meta.yaml and prompt.md, write vulnerable/ and fixed/ sources,")
    print("      add functional tests, write the exploit test, then run:")
    print(f"      uv run python harness/check_case.py cases/{new_id}")
    print(f"      uv run python scripts/leak_check.py cases/{new_id}")


if __name__ == "__main__":
    main()
