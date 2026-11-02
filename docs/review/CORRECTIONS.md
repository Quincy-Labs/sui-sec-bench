# Corrections

This replaces the earlier `INVENTORY`, `DISCREPANCIES`, `EXPLOIT-LADDER`, `CASE-AUDIT` and `VERDICT` docs, which contained unsupported claims. They aren't part of this repo.

| Earlier claim | Correction |
| --- | --- |
| Report and status tables | Replaced by tables generated from result files. |
| SSB-0001 is a cross-chain bridge bug in `get_swap_rate` | It's the Cetus incident case, in `math::scale`. |
| SSB-0002 diff | Vulnerable and fixed were swapped. Diffs are now generated from the case folders. |
| Leak terms "swift", "wormhole", "bascule" found in prompts and comments | They appear only in the `leak_terms` lists in `meta.yaml`. The leak scan is clean. |
| SSB-0002 test coverage complete | It lacked a driver-before-window test. Added in `tests_v2`. |
| SSB-0003 has no regrade for its other flaws | Short-key and threshold exploits added. Saved patches regraded; scores didn't change. |
| Exploit jump caused by feedback, no prompt teaching | The prompt teaches polarity and test construction. Results are labelled assisted. |
| Blind and prompt-taught runs don't exist | SSB-0001 runs exist in `results/`, `scaffold`, `exploit_v3` and `pilot_v3`. |
| Prompt-taught pilot 4/8 | `pilot_v3` is 3/6. |
| No model solved a patch | flint passed 1 sample on SSB-0002. |

## Thinking rerun

bonsai and qwen3.8 ran with thinking off from Oct 31 18:39 onward, set in `~/.lmstudio/.internal/user-concrete-model-default-config/`. `results/run3_thinking_on` reruns both on SSB-0002 and SSB-0003 with it on. `run2` is unchanged, and both runs are reported.

## Validation

`harness/regrade_v2.py` checks reference packages first: functional tests pass on both, and each exploit passes on vulnerable and fails on fixed. Results are in `results/regrade_v2/patch_regrade.json`.

## Open

- Whether qwen3.8 should get a larger token limit. It reached 32,768 tokens on 5 of 6 patch samples with thinking on.
- bonsai and qwen3.8 on SSB-0001 weren't rerun with thinking on.
- The devstral serving error on one detect sample.
- Whether detect should score location and class separately.
