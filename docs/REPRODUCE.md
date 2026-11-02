# Reproducing the pilot

Requires `uv`, Sui CLI 1.82.3 on `PATH`, and for model runs, an LM Studio server at `127.0.0.1:1234` with the models loaded on demand. Run everything from the repo root.

Rebuild tables and the report from existing grades:

```bash
uv run python leaderboard/build.py
```

Check cases for leak terms:

```bash
uv run python scripts/leak_check.py --all
```

Regrade saved patches with the extended tests (restricted bundle only):

```bash
uv run python harness/regrade_v2.py
```

Rerun the SSB-0002 and SSB-0003 models (overwrites nothing; choose an empty output directory). This repo doesn't include the reference exploits, so patches graded here aren't checked against them and their scores aren't comparable with the published ones:

```bash
bash scripts/run_pilot.sh results/my_run
```

The SSB-0001 exploit runs from Oct 30 to Oct 31 used earlier prompts that weren't saved, so they can't be reproduced exactly.

## Thinking-on rerun

Set `enableThinking` to true for bonsai and qwen3.8 in LM Studio, then:

```bash
bash scripts/run_pilot.sh results/run3_thinking_on prism-ml/bonsai-27b qwen/qwen3.8-27b
uv run python harness/regrade_v2.py run3_thinking_on patch_regrade_run3.json
```

## Adding a case

```bash
uv run python scripts/new_case.py
```

This copies `cases/_template` to the next free `SSB-####` id. Fill in `meta.yaml` and `prompt.md`, write the `vulnerable/` and `fixed/` sources, add functional tests, and write the exploit test. Then run these, using the new id:

```bash
uv run python harness/check_case.py cases/SSB-0004
uv run python scripts/leak_check.py cases/SSB-0004
```
