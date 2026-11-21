# External test results (run once)

- Code commit: `c0c7615` (rules unchanged since validation). Case list: `data/external_test_v1.csv`, sha256 matches `FREEZE.json`.
- 1,946 cases: 1,000 malicious (DataDog), 946 legitimate. Run in `check` mode only; nothing was installed.
- 41 UNKNOWN cases were re-run (`output/retry_unknown_results.jsonl`) and returned UNKNOWN again: they are packages npm has fully unpublished (no versions left), so there is nothing to check. The CLI fails closed on UNKNOWN (exit 4, install not run).

## Decisions by stratum

| Stratum | n | BLOCK | WARN | UNKNOWN | ALLOW |
|---|---:|---:|---:|---:|---:|
| DataDog malicious intent | 800 | 689 | 2 | 41 | 68 |
| DataDog compromised versions | 200 | 199 | 0 | 0 | 1 |
| npm popular | 300 | 0 | 0 | 0 | 300 |
| npm ordinary | 600 | 0 | 5 | 0 | 595 |
| Legitimate with install scripts | 46 | 0 | 27 | 0 | 19 |

Malicious BLOCKs by stage: 687 + 5 OSV known-malicious, 184 missing version, 12 missing package. The scoring stage itself blocked none here.

## Headline numbers

| View | Malicious stopped (BLOCK/WARN/UNKNOWN) | Malicious blocked | Legitimate blocked | Legitimate warned |
|---|---:|---:|---:|---:|
| As labelled (n=1,946) | 931/1000 (93.1%) | 888/1000 (88.8%) | 0/946 (0%) | 32/946 (3.4%) |
| Popular + ordinary only | | | 0/900 | 5/900 (0.56%) |

Block-only accuracy as labelled: 94.24%.

## Label review (after the run, not used to change anything)

65 of the 69 allowed "malicious" packages now resolve to npm's `0.0.1-security` placeholder: npm already removed the malicious code, so installing them is harmless today. The 4 remaining misses: `4`, `@toptal/picasso-accordion`, `amazon-data-kiosk-monorepo` (unpinned, so the current latest was checked), and `@joyfill/layouts@0.1.2-2773.beta.1` (pinned compromised version, no install script).

Excluding the 65 placeholders and 41 unpublished names (nothing malicious left to install): 890/894 malicious stopped (99.55%), 888/894 blocked (99.33%); block-only accuracy (888+946)/1840 = 99.67%.

## Known weaknesses

- Legitimate packages with install scripts are warned 59% of the time (27/46), above the 1% WARN budget for that group.
- Almost all malicious catches come from existence and OSV checks. Only 6 live malicious packages reached the scoring stage (2 warned, 4 allowed), too few to measure the scoring stage on this set.
