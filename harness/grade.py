"""Grade a results file by running the checks described in README.md.

Run from the repo root:
    uv run python harness/grade.py results/<run_id>.json

Grading rules:
- detect: strict = exact bug class and exact module::function. lenient = right
  class and right module (any function). Clean cases are graded on the found flag.
- patch: model files must all be under sources/ (never tests/); the patched
  package must build, pass functional tests, and fail the reference exploit test.
- exploit: the model test must pass on vulnerable/ and fail on fixed/.

Model-written tests run in a fresh temp copy of the package with a timeout.
Case folders are never modified.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import Case, load_cases, run_move_tests, validate_source_paths, write_package_with_sources


def _repair_partial(s: str) -> str | None:
    """Best-effort close of unclosed strings/arrays/objects in truncated JSON."""
    stack: list[str] = []
    in_str = False
    esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if not stack:
                return None
            stack.pop()
    if in_str:
        s = s + '"'
    s = s.rstrip()
    if s.endswith(","):
        s = s[:-1]
    s = re.sub(r":\s*$", "", s)
    s = re.sub(r'\s*,\s*"[^"]*"\s*$', "", s)
    while stack:
        s = s + ("}" if stack.pop() == "{" else "]")
    return s


def parse_json(raw: str) -> tuple[dict | None, str | None]:
    """Parse model output that may be wrapped in prose or code fences.

    Returns (dict_or_None, reason); reason is None on success.
    """
    if not raw or not raw.strip():
        return None, "empty"
    text = raw.strip()
    if "\u010a" in text or "\u0120" in text:
        # Some servers (LM Studio + devstral) return undecoded BPE merge tokens
        # in the content field: U+010A (newline merge) and U+0120 (space merge),
        # which breaks JSON parsing. Decode before attempting.
        text = text.replace("\u010a", "\n").replace("\u0120", " ")
    if "```" in text:
        m = re.search(r"```(?:json|move)?\s*(.*?)```", text, re.S)
        if m:
            text = m.group(1).strip()
    candidates = [text]
    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last > first:
        candidates.append(text[first : last + 1])
    for cand in candidates:
        try:
            value = json.loads(cand)
            return (value, None) if isinstance(value, dict) else (None, "not an object")
        except json.JSONDecodeError:
            pass
    if first != -1:
        repaired = _repair_partial(text[first:])
        if repaired:
            try:
                value = json.loads(repaired)
                if isinstance(value, dict):
                    return value, None
            except json.JSONDecodeError:
                pass
    return None, "unparseable"


def _norm_location(loc: object) -> str:
    parts = [p for p in re.split(r"[:.]+", str(loc or "").strip().lower()) if p]
    return "::".join(parts)


def _location_parts(loc: object) -> list[str]:
    return [p for p in _norm_location(loc).split("::") if p]


def _location_module(loc: object) -> str:
    """Move module containing the named function.

    Model output is often fully qualified (``case::math::scale``), so the
    module is the part just before the function, not the first element.
    """
    parts = _location_parts(loc)
    return parts[-2] if len(parts) >= 2 else ""


def _location_tail(loc: object, n: int = 2) -> list[str]:
    """Trailing path elements (module::function by default), for comparison."""
    return _location_parts(loc)[-n:]


def grade_detect(case: Case, raw: str, sample: dict) -> dict:
    meta = case.meta
    out, why = parse_json(raw)
    if out is None:
        return {"correct": False, "lenient": False, "reason": why, "raw_tail": raw[-300:] if raw else ""}
    found = bool(out.get("found", True))
    if meta["source"] == "clean":
        fp = found
        return {
            "correct": not fp,
            "lenient": not fp,
            "false_positive": fp,
            "class_claimed": out.get("bug_class"),
        }
    class_ok = out.get("bug_class") == meta["bug_class"]
    # Compare trailing module::function so fully qualified answers
    # ("case::math::scale") match the meta's relative path ("math::scale").
    location_matches = _location_tail(out.get("location", "")) == _location_tail(meta["bug_location"])
    strict = class_ok and location_matches
    lenient = class_ok and _location_module(
        out.get("location", "")
    ) == _location_module(meta["bug_location"])
    return {
        "correct": strict,
        "lenient": lenient,
        "class_ok": class_ok,
        "location_ok": location_matches,
        "found": found,
    }


def grade_patch(case: Case, raw: str, sample: dict) -> dict:
    out, why = parse_json(raw)
    files = (out or {}).get("files") or {}
    if not isinstance(files, dict) or not files:
        return {
            "correct": False,
            "functional_ok": False,
            "exploit_blocked": None,
            "reason": why or "no files",
        }
    unsafe = validate_source_paths(files)
    if unsafe:
        return {
            "correct": False,
            "functional_ok": False,
            "exploit_blocked": None,
            "reason": f"unsafe path(s) rejected: {', '.join(unsafe[:5])}",
        }
    with tempfile.TemporaryDirectory(prefix="ssb-patch-") as tmp:
        pkg = write_package_with_sources(case.path / "vulnerable", files, Path(tmp) / "patched")
        func = run_move_tests(pkg, [case.path / "tests" / "functional"])
        exp_files = list((case.path / "tests" / "exploit").glob("*.move"))
        if exp_files:
            exp = run_move_tests(pkg, [case.path / "tests" / "exploit"])
            exploit_blocked: bool | None = not exp.passed
        else:
            exp = None
            exploit_blocked = None  # exploit tests withheld; can't confirm the fix
    return {
        "correct": func.passed and exploit_blocked is True,
        "incomplete": exploit_blocked is None,
        "functional_ok": func.passed,
        "functional_phase": func.phase,
        "exploit_blocked": exploit_blocked,
        "exploit_phase": exp.phase if exp else None,
    }


def grade_exploit(case: Case, raw: str, sample: dict) -> dict:
    out, why = parse_json(raw)
    test = (out or {}).get("test_file")
    if not isinstance(test, str) or not test.strip():
        return {
            "correct": False,
            "passes_on_vulnerable": False,
            "fails_on_fixed": False,
            "reason": why or "no test",
        }
    vuln = run_move_tests(case.path / "vulnerable", [], {"model_exploit_tests.move": test})
    fixed = run_move_tests(case.path / "fixed", [], {"model_exploit_tests.move": test})
    return {
        "correct": vuln.passed and not fixed.passed,
        "passes_on_vulnerable": vuln.passed,
        "fails_on_fixed": not fixed.passed,
        "vulnerable_phase": vuln.phase,
        "fixed_phase": fixed.phase,
    }


GRADERS = {"detect": grade_detect, "patch": grade_patch, "exploit": grade_exploit}


def summarize(run: dict, cases_by_id: dict[str, Case]) -> dict:
    grades_by_case: dict[str, list[dict]] = {}
    for o in run["outputs"]:
        grades_by_case.setdefault(o["case"], []).append(o.get("grade") or {})

    def src(case_id: str) -> str | None:
        case = cases_by_id.get(case_id)
        return case.meta.get("source") if case else None

    def agg(key: str, source: str | None) -> dict:
        sel = [c for c in grades_by_case if source is None or src(c) == source]
        per_sample = [bool(g.get(key, False)) for c in sel for g in grades_by_case[c]]
        best = [any(bool(g.get(key, False)) for g in grades_by_case[c]) for c in sel]
        return {
            "cases": len(sel),
            "samples": len(per_sample),
            "best_at_k": sum(best) / len(sel) if sel else None,
            "mean": sum(per_sample) / len(per_sample) if per_sample else None,
        }

    is_detect = run["task"] == "detect"
    len_key = "lenient" if is_detect else "correct"
    fp_vals = [
        bool(g.get("false_positive")) for c, gs in grades_by_case.items() for g in gs if src(c) == "clean"
    ]
    return {
        "task": run["task"],
        "model": run["model"],
        "cases": len(grades_by_case),
        "samples_total": len(run["outputs"]),
        "strict": agg("correct", None),
        "lenient": agg(len_key, None),
        "splits": {
            "incident": {"strict": agg("correct", "incident"), "lenient": agg(len_key, "incident")},
            "audit": {"strict": agg("correct", "audit"), "lenient": agg(len_key, "audit")},
            "clean": {"strict": agg("correct", "clean"), "lenient": agg(len_key, "clean")},
        },
        "false_positive_rate": sum(fp_vals) / len(fp_vals) if fp_vals else None,
        "per_case": {
            c: {
                "source": src(c),
                "n_samples": len(gs),
                "correct_any": any(g.get("correct", False) for g in gs),
                "lenient_any": any(g.get("lenient", g.get("correct", False)) for g in gs),
            }
            for c, gs in sorted(grades_by_case.items())
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", type=Path)
    ap.add_argument("--cases", type=Path, default=Path("cases"))
    args = ap.parse_args()
    run = json.loads(args.results.read_text())
    if run["task"] not in GRADERS:
        raise SystemExit(f"no grader for task {run['task']!r}")
    cases_by_id = {c.id: c for c in load_cases(args.cases)}
    grader = GRADERS[run["task"]]
    for o in run["outputs"]:
        case = cases_by_id.get(o["case"])
        if case is None:
            o["grade"] = {"correct": False, "lenient": False, "reason": "case not found"}
            continue
        o["grade"] = grader(case, o.get("raw", ""), o)
        print(o["case"], o["sample"], json.dumps(o["grade"])[:200])
    run["summary"] = summarize(run, cases_by_id)
    args.results.write_text(json.dumps(run, indent=2))
    print("summary", json.dumps(run["summary"], indent=1))


if __name__ == "__main__":
    main()
