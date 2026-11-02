#!/bin/bash
# Run SSB-0002 and SSB-0003 across the six models, one model at a time.
# Usage: bash scripts/run_pilot.sh <empty-output-dir> [model ...]
set -o pipefail
cd "$(dirname "$0")/.." || exit 1
OUT="${1:?usage: run_pilot.sh <empty-output-dir> [model ...]}"
shift
mkdir -p "$OUT"

MODELS=(
  "qwen3-coder-30b-a3b-instruct-mlx"
  "mistralai/devstral-small-2-2512"
  "openai/gpt-oss-20b"
  "recursivesi/flint"
  "prism-ml/bonsai-27b"
  "qwen/qwen3.8-27b"
)
[ $# -gt 0 ] && MODELS=("$@")

for model in "${MODELS[@]}"; do
  m="${model//\//_}"
  for task in detect patch; do
    uv run python harness/run.py --model "lmstudio:$model" --task "$task" \
      --case SSB-0002 --case SSB-0003 --samples 3 --thinking default \
      --max-tokens 32768 --out "$OUT/${m}__${task}.json"
    uv run python harness/grade.py "$OUT/${m}__${task}.json" >/dev/null
  done
  uv run python harness/run.py --model "lmstudio:$model" --task exploit \
    --case SSB-0002 --case SSB-0003 --samples 1 --agentic --iters 5 \
    --thinking default --max-tokens 32768 --out "$OUT/${m}__exploit.json"
  uv run python harness/grade.py "$OUT/${m}__exploit.json" >/dev/null
done
