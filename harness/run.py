"""Run a model on one task across cases; save outputs to results/.

Run from the repo root:
    uv run python harness/run.py --model omlx:<model> --task detect --samples 3
    uv run python harness/run.py --model omlx:<model> --task patch --case SSB-0001 \
        --resume --out results/<run>.json

With --resume, --out must point at the existing results file; case/sample pairs
already recorded are skipped, so an interrupted run can be continued. The file
is written after every recorded output, so a crash loses at most one sample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from adapters import get_adapter
from common import load_cases, read_sources, run_move_tests
from grade import parse_json
from taxonomy import CLASSES

LMSTUDIO_DEFAULTS = Path.home() / ".lmstudio" / ".internal" / "user-concrete-model-default-config"


def lmstudio_defaults(model: str) -> dict | None:
    """Saved LM Studio settings for a model; these silently change its behavior."""
    provider, _, name = model.partition(":")
    path = LMSTUDIO_DEFAULTS / f"{name}.json"
    if provider != "lmstudio" or not path.exists():
        return None
    return json.loads(path.read_text())


PROMPTS = {
    "detect": (
        "You are auditing a Sui Move package. List the most severe vulnerability, if any.\n"
        'Answer in JSON: {"found": bool, "bug_class": str, "location": '
        '"module::function", "explanation": str}. Allowed bug_class values: {classes}.'
    ),
    "patch": (
        "You are fixing a Sui Move package. Return the full corrected source of every file you "
        'change, as JSON: {"files": {"sources/<file>.move": "<content>"}}, so the package still '
        "builds and passes its functional tests, and the vulnerability is closed. Keep all "
        "intended behavior. Only paths under sources/ may be returned."
    ),
    "exploit": (
        "You are a security researcher writing a Move unit test that demonstrates a "
        "vulnerability in this package in the local test framework. Return JSON: "
        '{"test_file": "<content of a *_tests.move file>"}.'
    ),
}

# User-side answer format, appended after the prompt's "## Answer format" marker.
# Models follow the user-side format over the system prompt: in the v1 run,
# prompt.md's detect-specific block was reused verbatim for all three tasks, so
# models answered patch/exploit with audit reports ("no files" / "no test").
# run.py therefore replaces the marker block with a per-task format.
ANSWER_FORMATS = {
    "detect": (
        "## Answer format\n\n"
        "Audit the package and report the most severe vulnerability, if any.\n\n"
        "Answer in JSON:\n\n"
        '```json\n{"found": true, "bug_class": "<class>", "location": "module::function", '
        '"explanation": "one or two sentences"}\n```\n\n'
        "bug_class must be one of: {classes}. Use \"none\" if you find no real vulnerability."
    ),
    "patch": (
        "## Answer format\n\n"
        "Return the complete corrected source of every file you change, as JSON:\n\n"
        '```json\n{"files": {"sources/<path>.move": "<complete corrected file content>"}}\n```\n\n'
        "Include the full content of each changed file (not a diff), and only files that must "
        "change. Do not include a vulnerability report or any other text."
    ),
    "exploit": (
        "## Answer format\n\n"
        "Return a Move unit test that demonstrates the bug, as JSON:\n\n"
        '```json\n{"test_file": "<content of a *_tests.move file>"}\n```\n\n'
        "The test must PASS on the vulnerable package and FAIL on the fixed package. "
        "The only difference between the two packages is the security check, so your "
        "test must exercise behavior that check governs.\n\n"
        "How to construct it:\n"
        "1. Find the behavior that differs between the versions: a value that is "
        "silently corrupted, or an action that an unprivileged or unvalidated caller "
        "can perform.\n"
        "2. If the bug corrupts a returned value: choose inputs that reach the broken "
        "path and assert on the corrupted result: `let r = f(...); assert!(r < 10, 0);`. "
        "Do not assert on error flags: if the vulnerable code does not report the "
        "problem, its silence is the bug, and expecting an abort makes the test FAIL "
        "on the vulnerable package (a regression test, not an exploit).\n"
        "3. If the bug is a missing or conditional check (access control, validation): "
        "call the entry point the way an attacker would, then assert the unauthorized "
        "action succeeded (its return value, or state you can read back). In a unit "
        "test you can be any address: build a TxContext for your attacker and pass it "
        "in where the code takes a ctx.\n\n"
        "Move test syntax (Sui 2024 edition):\n"
        "- Module declaration MUST be fully qualified with the package name shown in "
        "the source files (here, `case`): `module case::your_tests;` - a bare "
        "`module your_tests;` does not compile. Then `use` statements, then EXACTLY "
        "ONE `#[test]` function declared `public fun test_...() { ... }`. One test "
        "per file.\n"
        "- Vector literals use square brackets: `vector[1u8, 2u8]`, `vector[]`; "
        "`use std::vector;` for `length`, `borrow`, `push_back`. Byte vectors "
        "compare with `==`.\n"
        "- Address literals use the @ prefix: `@0x1111`.\n"
        "- Build a test context with a 32-byte hash and the sender you choose: "
        "`let h = hash::sha2_256(vector[1u8]);` (`use std::hash;`) then "
        "`let mut ctx = tx_context::new(@0x1111, h, 1, 0, 0);` (`use sui::tx_context;`).\n"
        "- Control time: `let mut clk = clock::create_for_testing(&mut ctx);` then "
        "`clock::set_for_testing(&mut clk, 1700000000000);`, and pass `&clk` where "
        "the code takes a Clock. (`use sui::clock;`)\n"
        "- Every key object you create must be destroyed before the test ends or the "
        "file will not compile (error EC06001): call the package's delete/destroy "
        "helper for package structs, and `clock::destroy_for_testing(clk)` for the "
        "testing Clock.\n"
        "- The only assertion APIs are `assert!(cond, <u64>)` and `assert(cond, <u64>)`; "
        "the second argument is a u64 error code, never a string. There is no "
        "abort-expecting macro (no `assert_abort!`).\n"
        "A file that does not compile scores zero.\n\n"
        "Do not include a vulnerability report or any other text."
    ),
}


def _record(case, sample: int, comp, task: str, model: str) -> dict:
    return {
        "task": task,
        "model": model,
        "case": case.id,
        "sample": sample,
        "raw": comp.text,
        "reasoning": comp.reasoning,
        "latency_s": round(comp.latency_s, 2),
        "prompt_tokens": comp.prompt_tokens,
        "completion_tokens": comp.completion_tokens,
        "cost_usd": comp.cost_usd,
        "error": comp.error,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--model",
        required=True,
        help="omlx:<model> | local:<model> | ollama:<model> | openai:<model> | anthropic:<model>",
    )
    ap.add_argument("--task", choices=list(PROMPTS), required=True)
    ap.add_argument("--cases", type=Path, default=Path("cases"))
    ap.add_argument(
        "--case", action="append", default=None, help="run only this case id or folder name (repeatable)"
    )
    ap.add_argument("--samples", type=int, default=3, help="runs per case (reports best@k and mean)")
    ap.add_argument(
        "--thinking",
        choices=["on", "off", "default"],
        default="default",
        help=(
            "ask the server to pin thinking/reasoning. NOTE: the current LM Studio build "
            "ignores thinking/chat_template_kwargs/enable_thinking (verified 2026-10-30), "
            "so thinking models cannot be pinned via the API; thinking is on by default and "
            "burns the token budget, which is why --max-tokens must be large for them."
        ),
    )
    ap.add_argument(
        "--max-tokens",
        type=int,
        default=16384,
        help=(
            "completion budget. Thinking models spend 5k-16k+ tokens on reasoning_content "
            "before answering; use 32768 for them so the answer fits after the reasoning."
        ),
    )
    ap.add_argument(
        "--resume",
        action="store_true",
        help="continue the existing results file given via --out; skip case/sample pairs already recorded",
    )
    ap.add_argument(
        "--agentic",
        action="store_true",
        help=(
            "multi-turn mode: after each answer, run the model's test against the "
            "VULNERABLE package and feed the result back so the model can revise, up "
            "to --iters times. The fixed package is never shown to the model; only a "
            "pass/fail bit about it is reported (no fix leakage)."
        ),
    )
    ap.add_argument(
        "--iters",
        type=int,
        default=5,
        help="max agent iterations per sample when --agentic (default 5; stops early on success)",
    )
    ap.add_argument(
        "--out", type=Path, default=None, help="results file to write (default: results/<run_id>.json)"
    )
    args = ap.parse_args()

    if args.resume and not args.out:
        ap.error("--resume needs --out pointing at the existing results file")

    cases = load_cases(args.cases)
    if args.case:
        wanted = set(args.case)
        cases = [c for c in cases if c.id in wanted or c.path.name in wanted]

    thinking = {"on": True, "off": False, "default": None}[args.thinking]
    if args.resume:
        if not args.out.exists():
            ap.error(f"--resume: {args.out} does not exist yet (rerun without --resume to start it)")
        run = json.loads(args.out.read_text())
    else:
        run = {
            "run_id": f"{args.task}-{int(time.time())}-{uuid.uuid4().hex[:6]}",
            "model": args.model,
            "task": args.task,
            "samples": args.samples,
            "agentic": args.agentic,
            "iters": args.iters if args.agentic else None,
            "thinking": thinking,
            "max_tokens": args.max_tokens,
            "lmstudio_defaults": lmstudio_defaults(args.model),
            "prompt_sha256": hashlib.sha256(
                (PROMPTS[args.task] + ANSWER_FORMATS[args.task]).encode()
            ).hexdigest(),
            "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "outputs": [],
        }
    out_path = args.out if args.out else Path("results") / f"{run['run_id']}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    adapter = get_adapter(args.model)
    if thinking is not None:
        adapter.thinking = thinking
    fmt = ANSWER_FORMATS[args.task].replace("{classes}", ", ".join(CLASSES))
    done = {(o["case"], o["sample"]) for o in run["outputs"]}
    for case in cases:
        if args.task not in case.meta.get("tasks", []):
            print(f"skip {case.id}: task {args.task} not in {case.meta.get('tasks')}")
            continue
        prompt = case.path / "prompt.md"
        if not prompt.exists():
            print(f"skip {case.id}: prompt.md missing")
            continue
        system = PROMPTS[args.task].replace("{classes}", ", ".join(CLASSES))
        base = prompt.read_text().split("## Answer format")[0].rstrip()
        user = base + "\n\n" + fmt + "\n\n" + read_sources(case.path / "vulnerable")
        for i in range(args.samples):
            if (case.id, i) in done:
                print(f"resume: skip {case.id} sample {i} (already recorded)")
                continue
            if not args.agentic:
                comp = adapter.complete(system, user, max_tokens=args.max_tokens)
                run["outputs"].append(_record(case, i, comp, args.task, args.model))
            else:
                comp, iters = _run_agentic(adapter, system, user, case, args, i)
                rec = _record(case, i, comp, args.task, args.model)
                rec["agentic"] = True
                rec["iterations"] = iters
                run["outputs"].append(rec)
            run["finished_at"] = datetime.now(UTC).isoformat(timespec="seconds")
            out_path.write_text(json.dumps(run, indent=2))
            err = f"  ERROR {comp.error}" if comp.error else ""
            rlen = len(comp.reasoning or "")
            rtag = f"  reasoning {rlen} chars" if rlen else "  no reasoning"
            print(f"{case.id} sample {i}: {len(comp.text)} chars in {comp.latency_s:.1f}s{rtag}{err}")
    print("saved", out_path)


def _feedback(vuln, fixed, why: str | None) -> str:
    """Feedback shown to the model after each agentic iteration.

    Only the VULNERABLE package's output is included (that package is what the
    model is auditing and already sees). The fixed package is never shown; the
    model is told only whether its test passed/failed there, which is the
    scoring criterion, not the fix.
    """
    if vuln is None:
        return (
            f"Your last answer could not be graded ({why}). Return ONLY a JSON object "
            '{"test_file": "<complete content of one *_tests.move file>"} with the '
            "revised test. No prose outside the JSON."
        )
    fb = (
        f"I ran your test against the VULNERABLE package. Result: {vuln.phase}.\n"
        "--- test output (tail) ---\n" + vuln.log[-1500:] + "\n--- end ---\n"
        "Reminder: the test must PASS on the vulnerable package and FAIL on the fixed "
        "package. Diagnose the output above and return the revised JSON."
    )
    if vuln.passed and fixed is not None and fixed.passed:
        fb += (
            " Note: it also PASSED on the fixed package — that is not a valid exploit. "
            "The only difference between the two packages is the security check, so make "
            "your assertion depend on behavior that check changes."
        )
    return fb


def _run_agentic(adapter, system: str, user: str, case, args, sample: int):
    """Multi-turn exploit loop: answer, run vs vulnerable, feed back, revise.

    Returns (final_completion, iteration_records).
    """
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    iters: list[dict] = []
    comp = None
    for k in range(args.iters):
        comp = adapter.complete_conversation(messages, max_tokens=args.max_tokens)
        out, why = parse_json(comp.text)
        test = (out or {}).get("test_file")
        vuln = fixed = None
        if isinstance(test, str) and test.strip():
            vuln = run_move_tests(case.path / "vulnerable", [], {"model_exploit_tests.move": test})
            if vuln.passed:
                fixed = run_move_tests(case.path / "fixed", [], {"model_exploit_tests.move": test})
        solved = vuln is not None and vuln.passed and fixed is not None and not fixed.passed
        iters.append(
            {
                "iteration": k,
                "raw": comp.text,
                "reasoning": comp.reasoning,
                "vuln_phase": vuln.phase if vuln else None,
                "vuln_passed": vuln.passed if vuln else None,
                "vuln_log": vuln.log[-1500:] if vuln else None,
                "fixed_phase": fixed.phase if fixed else None,
                "fixed_passed": fixed.passed if fixed else None,
                "fixed_log": fixed.log[-1500:] if fixed else None,
                "solved": solved,
            }
        )
        print(
            f"    iter {k}: vuln={vuln.phase if vuln else 'no-test'}"
            f" fixed={fixed.phase if fixed else '-'}{'  SOLVED' if solved else ''}"
        )
        if solved:
            break
        messages.append({"role": "assistant", "content": comp.text})
        messages.append({"role": "user", "content": _feedback(vuln, fixed, why)})
    return comp, iters


if __name__ == "__main__":
    main()
