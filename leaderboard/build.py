"""Generate leaderboard tables and the pilot report from graded result files.

Run from the repo root:
    uv run python leaderboard/build.py

Reads results/*.json (Oct 30 SSB-0001 baseline), results/{scaffold,exploit_v3,
pilot_v3,agentic_v3}/ (SSB-0001 exploit conditions), results/run2/ (SSB-0002 and
SSB-0003), results/run3_thinking_on/ (the same cases with thinking on for two
models) and results/regrade_v2/. Writes leaderboard/README.md,
leaderboard/results.json and, from docs/PILOT-REPORT.template.md,
docs/PILOT-REPORT-clean.md. Every number in those files comes from this script.
"""

import difflib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
MODELS = [
    "recursivesi/flint",
    "qwen/qwen3.8-27b",
    "qwen3-coder-30b-a3b-instruct-mlx",
    "openai/gpt-oss-20b",
    "prism-ml/bonsai-27b",
    "mistralai/devstral-small-2-2512",
]
NEW_CASES = ["SSB-0002", "SSB-0003"]
THINKING_MODELS = ["prism-ml/bonsai-27b", "qwen/qwen3.8-27b"]
TOKEN_LIMIT = 32768
EXPLOIT_CONDITIONS = ["scaffold", "exploit_v3", "pilot_v3"]
DIFF_FILES = {
    "SSB-0001": "sources/math.move",
    "SSB-0002": "sources/fulfill.move",
    "SSB-0003": "sources/consortium.move",
}


def load(directory: Path, model: str, task: str) -> dict:
    return json.loads((directory / f"{model.replace('/', '_')}__{task}.json").read_text())


def outputs(run: dict, case: str) -> list[dict]:
    return [o for o in run["outputs"] if o["case"] == case]


def passes(outs: list[dict], key: str = "correct") -> int:
    return sum(bool((o.get("grade") or {}).get(key)) for o in outs)


def frac(outs: list[dict], key: str = "correct") -> str:
    return f"{passes(outs, key)}/{len(outs)}"


def table(headers: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def avg_tokens(run: dict) -> int:
    outs = run["outputs"]
    return round(sum(o.get("completion_tokens") or 0 for o in outs) / len(outs))


def at_limit(outs: list[dict]) -> int:
    return sum(1 for o in outs if (o.get("completion_tokens") or 0) >= TOKEN_LIMIT - 1)


def case_stats(directory: Path, regrade: dict, model: str) -> tuple[dict, dict]:
    detect = load(directory, model, "detect")
    patch = load(directory, model, "patch")
    exploit = load(directory, model, "exploit")
    cases = {}
    for case in NEW_CASES:
        d, p, e = outputs(detect, case), outputs(patch, case), outputs(exploit, case)
        v2 = [s for s in regrade["samples"] if s["model"] == model and s["case"] == case]
        cases[case] = {
            "detect": {
                "strict": passes(d),
                "lenient": passes(d, "lenient"),
                "location_ok": passes(d, "location_ok"),
                "class_ok": passes(d, "class_ok"),
                "samples": len(d),
                "serving_errors": sum(1 for o in d if o.get("error")),
                "at_token_limit": at_limit(d),
            },
            "patch": {
                "original": passes(p),
                "v2": sum(s["grade"]["correct"] for s in v2),
                "samples": len(p),
                "empty": sum(1 for o in p if o["grade"].get("reason") in ("no files", "empty")),
                "unparseable": sum(1 for o in p if o["grade"].get("reason") == "unparseable"),
                "build_failed": sum(1 for o in p if o["grade"].get("functional_phase") == "build_failed"),
                "functional_failed": sum(1 for o in p if o["grade"].get("functional_phase") == "test_failed"),
                "exploit_not_blocked": sum(1 for o in p if o["grade"].get("exploit_blocked") is False),
                "at_token_limit": at_limit(p),
            },
            "exploit": {
                "correct": passes(e),
                "samples": len(e),
                "iterations": len(e[0].get("iterations") or []),
            },
        }
    tokens = {"detect": avg_tokens(detect), "patch": avg_tokens(patch)}
    return cases, tokens


def totals(by_model: dict) -> dict:
    def total(task: str, key: str) -> int:
        return sum(m[c][task][key] for m in by_model.values() for c in NEW_CASES)

    return {
        "exploit": f"{total('exploit', 'correct')}/{total('exploit', 'samples')}",
        "patch": f"{total('patch', 'original')}/{total('patch', 'samples')}",
        "patch_extended": f"{total('patch', 'v2')}/{total('patch', 'samples')}",
        "detect": f"{total('detect', 'strict')}/{total('detect', 'samples')}",
        "location": f"{total('detect', 'location_ok')}/{total('detect', 'samples')}",
        "class": f"{total('detect', 'class_ok')}/{total('detect', 'samples')}",
    }


def collect() -> dict:
    regrade = json.loads((RESULTS / "regrade_v2" / "patch_regrade.json").read_text())
    regrade3 = json.loads((RESULTS / "regrade_v2" / "patch_regrade_run3.json").read_text())
    data: dict = {"models": {}, "references": regrade["references"], "thinking_on": {}}
    for model in THINKING_MODELS:
        cases, tokens = case_stats(RESULTS / "run3_thinking_on", regrade3, model)
        data["thinking_on"][model] = {"cases": cases, "tokens": tokens}
    for model in MODELS:
        cases, tokens = case_stats(RESULTS / "run2", regrade, model)
        m: dict = {"cases": cases, "ssb_0001": {}}
        base = {t: load(RESULTS, model, t) for t in ("detect", "patch", "exploit")}
        m["ssb_0001"] = {
            "baseline_detect": frac(base["detect"]["outputs"]),
            "baseline_patch": frac(base["patch"]["outputs"]),
            "baseline_exploit": frac(base["exploit"]["outputs"]),
            **{c: frac(load(RESULTS / c, model, "exploit")["outputs"]) for c in EXPLOIT_CONDITIONS},
        }
        agentic = load(RESULTS / "agentic_v3", model, "exploit")["outputs"][0]
        m["ssb_0001"]["agentic"] = bool(agentic["grade"].get("correct"))
        m["ssb_0001"]["agentic_iterations"] = len(agentic.get("iterations") or [])
        m["tokens"] = {
            "oct30_patch": avg_tokens(base["patch"]),
            "nov1_patch": tokens["patch"],
            "oct30_detect": avg_tokens(base["detect"]),
            "nov1_detect": tokens["detect"],
        }
        data["models"][model] = m
    as_run = {m: data["models"][m]["cases"] for m in MODELS}
    data["totals"] = {
        "as_run": totals(as_run),
        "thinking_on": totals({**as_run, **{m: t["cases"] for m, t in data["thinking_on"].items()}}),
    }
    return data


def tables(data: dict) -> str:
    ms = data["models"]
    case_cell = lambda m, case, task, key: ms[m]["cases"][case][task][key]

    def n_of(m, case, task, key):
        return f"{case_cell(m, case, task, key)}/{case_cell(m, case, task, 'samples')}"

    detect = [
        [m]
        + [n_of(m, c, "detect", k) for c in NEW_CASES for k in ("strict", "location_ok", "class_ok")]
        + [sum(case_cell(m, c, "detect", "serving_errors") for c in NEW_CASES)]
        for m in MODELS
    ]
    patch = [
        [m]
        + [n_of(m, c, "patch", k) for c in NEW_CASES for k in ("original", "v2")]
        + [
            sum(case_cell(m, c, "patch", k) for c in NEW_CASES)
            for k in ("empty", "unparseable", "build_failed", "functional_failed", "exploit_not_blocked")
        ]
        for m in MODELS
    ]
    exploit = [
        [m]
        + [
            f"{n_of(m, c, 'exploit', 'correct')} ({case_cell(m, c, 'exploit', 'iterations')} iter)"
            for c in NEW_CASES
        ]
        for m in MODELS
    ]
    ssb1 = [
        [
            m,
            ms[m]["ssb_0001"]["baseline_detect"],
            ms[m]["ssb_0001"]["baseline_patch"],
            ms[m]["ssb_0001"]["baseline_exploit"],
            ms[m]["ssb_0001"]["scaffold"],
            ms[m]["ssb_0001"]["exploit_v3"],
            ms[m]["ssb_0001"]["pilot_v3"],
            f"{'1/1' if ms[m]['ssb_0001']['agentic'] else '0/1'} ({ms[m]['ssb_0001']['agentic_iterations']} iter)",
        ]
        for m in MODELS
    ]
    tokens = [
        [m, *(ms[m]["tokens"][k] for k in ("oct30_detect", "nov1_detect", "oct30_patch", "nov1_patch"))]
        for m in MODELS
    ]
    on = data["thinking_on"]

    def both(m, task, key):
        off_n = sum(ms[m]["cases"][c][task][key] for c in NEW_CASES)
        on_n = sum(on[m]["cases"][c][task][key] for c in NEW_CASES)
        n = sum(on[m]["cases"][c][task]["samples"] for c in NEW_CASES)
        return f"{off_n}/{n}", f"{on_n}/{n}"

    thinking = [
        [m, *both(m, "detect", "strict"), *both(m, "detect", "location_ok"), *both(m, "patch", "v2"),
         *both(m, "patch", "empty"), *both(m, "exploit", "correct"),
         on[m]["tokens"]["detect"], on[m]["tokens"]["patch"],
         sum(on[m]["cases"][c][t]["at_token_limit"] for c in NEW_CASES for t in ("detect", "patch"))]
        for m in THINKING_MODELS
    ]
    return "\n\n".join(
        [
            "### Thinking off and on: bonsai and qwen3.8 on SSB-0002 and SSB-0003\n\n"
            "The other tables show the thinking-off run. Token and limit columns are for the "
            "thinking-on run, and the limit column counts single-shot samples.\n\n"
            + table(
                ["Model", "Detect off", "Detect on", "Location off", "Location on", "Patch off", "Patch on", "Empty patch off", "Empty patch on", "Exploit off", "Exploit on", "Detect tokens on", "Patch tokens on", "At token limit"],
                thinking,
            ),
            "### Detect: SSB-0002 and SSB-0003 (single-shot)\n\n"
            + table(
                ["Model", "0002 strict", "0002 location", "0002 class", "0003 strict", "0003 location", "0003 class", "Serving errors"],
                detect,
            ),
            "### Patch: SSB-0002 and SSB-0003 (single-shot)\n\n"
            "\"Original\" is the grade from the run. \"Extended\" adds the tests in `tests_v2`. "
            "The failure columns describe the original grades, across both cases.\n\n"
            + table(
                ["Model", "0002 original", "0002 extended", "0003 original", "0003 extended", "Empty", "Unparseable", "Build failed", "Functional failed", "Exploit not blocked"],
                patch,
            ),
            "### Exploit: SSB-0002 and SSB-0003 (assisted, agentic, up to 5 iterations)\n\n"
            + table(["Model", "SSB-0002", "SSB-0003"], exploit),
            "### SSB-0001: baseline tasks and exploit conditions\n\n"
            "Exploit prompts changed between these runs and weren't saved with them, so the columns "
            "aren't controlled comparisons.\n\n"
            + table(
                ["Model", "Detect Oct 30", "Patch Oct 30", "Exploit Oct 30", "Exploit scaffold", "Exploit v3", "Exploit pilot", "Exploit agentic"],
                ssb1,
            ),
            "### Average completion tokens per sample\n\n"
            + table(["Model", "Detect Oct 30", "Detect Nov 1", "Patch Oct 30", "Patch Nov 1"], tokens),
        ]
    )


def diffs() -> str:
    blocks = []
    for case, rel in DIFF_FILES.items():
        path = ROOT / "cases" / case
        lines = difflib.unified_diff(
            (path / "vulnerable" / rel).read_text().splitlines(),
            (path / "fixed" / rel).read_text().splitlines(),
            f"vulnerable/{rel}",
            f"fixed/{rel}",
            lineterm="",
            n=2,
        )
        blocks.append(f"### {case}\n\n```diff\n" + "\n".join(lines) + "\n```")
    return "\n\n".join(blocks)


def main() -> None:
    data = collect()
    rendered = tables(data)
    (ROOT / "leaderboard" / "results.json").write_text(json.dumps(data, indent=2) + "\n")
    (ROOT / "leaderboard" / "README.md").write_text(
        "# SSB Pilot Results\n\nGenerated by `leaderboard/build.py`. "
        "This is a small pilot, so these tables aren't a ranking.\n\n" + rendered + "\n"
    )
    template = (ROOT / "docs" / "PILOT-REPORT.template.md").read_text()
    for label, values in data["totals"].items():
        for key, value in values.items():
            template = template.replace("{{%s.%s}}" % (label, key), value)
    (ROOT / "docs" / "PILOT-REPORT-clean.md").write_text(
        template.replace("{{TABLES}}", rendered).replace("{{DIFFS}}", diffs())
    )


if __name__ == "__main__":
    main()
