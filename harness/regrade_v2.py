"""Regrade saved patches against the original tests plus cases/*/tests_v2.

Run from the repo root:
    uv run python harness/regrade_v2.py [run-dir] [output-name]

Saved runs are read only. Defaults read results/run2 and write
results/regrade_v2/patch_regrade.json. Output holds grades only, no model text. Each exploit runs alone so a patch gets credit
per flaw. A sample passes only if every functional test passes and every exploit
is blocked. Reference packages are checked first, and the script stops if the
tests don't separate vulnerable from fixed.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Case, load_cases, run_move_tests, write_package_with_sources
from grade import parse_json

ROOT = Path(__file__).resolve().parents[1]
CASE_IDS = ("SSB-0002", "SSB-0003")


def functional_dirs(case: Case) -> list[Path]:
    return [case.path / "tests" / "functional", case.path / "tests_v2" / "functional"]


def exploit_files(case: Case) -> list[Path]:
    dirs = [case.path / "tests" / "exploit", case.path / "tests_v2" / "exploit"]
    return [f for d in dirs if d.exists() for f in sorted(d.glob("*.move"))]


def exploit_results(pkg: Path, case: Case) -> dict[str, bool]:
    """Exploit file name -> whether it passed on pkg."""
    return {
        f.name: run_move_tests(pkg, [], {f.name: f.read_text()}).passed for f in exploit_files(case)
    }


def check_reference(case: Case) -> dict:
    vuln = case.path / "vulnerable"
    fixed = case.path / "fixed"
    return {
        "functional_vulnerable": run_move_tests(vuln, functional_dirs(case)).passed,
        "functional_fixed": run_move_tests(fixed, functional_dirs(case)).passed,
        "exploits_pass_on_vulnerable": exploit_results(vuln, case),
        "exploits_pass_on_fixed": exploit_results(fixed, case),
    }


def reference_ok(ref: dict) -> bool:
    return (
        ref["functional_vulnerable"]
        and ref["functional_fixed"]
        and all(ref["exploits_pass_on_vulnerable"].values())
        and not any(ref["exploits_pass_on_fixed"].values())
    )


def regrade_sample(case: Case, raw: str) -> dict:
    out, why = parse_json(raw)
    files = (out or {}).get("files") or {}
    if not isinstance(files, dict) or not files:
        return {"correct": False, "functional_ok": False, "reason": why or "no files"}
    with tempfile.TemporaryDirectory(prefix="ssb-regrade-") as tmp:
        pkg = write_package_with_sources(case.path / "vulnerable", files, Path(tmp) / "patched")
        func = run_move_tests(pkg, functional_dirs(case))
        if not func.passed:
            return {"correct": False, "functional_ok": False, "functional_phase": func.phase}
        passed = exploit_results(pkg, case)
    blocked = {name: not ok for name, ok in passed.items()}
    return {
        "correct": all(blocked.values()),
        "functional_ok": True,
        "functional_phase": func.phase,
        "exploits_blocked": blocked,
    }


def main() -> None:
    run_dir = sys.argv[1] if len(sys.argv) > 1 else "run2"
    out_name = sys.argv[2] if len(sys.argv) > 2 else "patch_regrade.json"
    cases = {c.id: c for c in load_cases(ROOT / "cases") if c.id in CASE_IDS}
    missing = [cid for cid, c in cases.items() if not exploit_files(c)]
    if missing or len(cases) != len(CASE_IDS):
        raise SystemExit(
            f"exploit tests missing for {missing or 'some cases'}; "
            "regrading needs the restricted bundle. Nothing written."
        )
    run_files = sorted((ROOT / "results" / run_dir).glob("*__patch.json"))
    runs = [json.loads(f.read_text()) for f in run_files]
    # Some outputs are empty (token limit), but a run with no text at all was stripped.
    if not runs or not any(o.get("raw") for r in runs for o in r["outputs"]):
        raise SystemExit(
            f"results/{run_dir} has no patch runs or no raw model outputs; "
            "regrading needs the restricted bundle. Nothing written."
        )
    references = {cid: check_reference(c) for cid, c in cases.items()}
    print(json.dumps(references, indent=1), flush=True)
    if not all(reference_ok(r) for r in references.values()):
        raise SystemExit("reference packages failed the v2 tests; nothing regraded")
    samples = []
    for run in runs:
        for o in run["outputs"]:
            grade = regrade_sample(cases[o["case"]], o.get("raw") or "")
            samples.append(
                {
                    "model": run["model"].removeprefix("lmstudio:"),
                    "case": o["case"],
                    "sample": o["sample"],
                    "original_correct": bool(o["grade"].get("correct")),
                    "grade": grade,
                }
            )
            print(samples[-1], flush=True)
    dest = ROOT / "results" / "regrade_v2"
    dest.mkdir(exist_ok=True)
    (dest / out_name).write_text(
        json.dumps({"references": references, "samples": samples}, indent=2)
    )


if __name__ == "__main__":
    main()
