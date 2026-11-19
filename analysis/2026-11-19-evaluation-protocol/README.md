# Evaluation protocol and dataset-overlap report (2026-11-19)

**Scope:** planning/protocol only. No production code, weights, thresholds, or dataset labels were modified. Baseline artifacts in `analysis/2026-11-04-npmanalysis-accuracy/` remain unchanged.

## What this folder contains

- `data/npmanalysis_package_splits.csv` — per-case assignment of every NPMAnalysis rebuilt case to `dev` or `val`, package-grouped (all versions of a package stay together), stratified by package label stratum.
- `data/split_summary.json` — split counts and seed.
- `output/baseline_metrics.json` / `output/baseline_metrics.md` — frozen baseline metrics recomputed from preserved `check-results.cli.jsonl`, reported for all/dev/val and for separated evaluation stages.
- `EVALUATION_PLAN.md` — protocol, external-dataset assessment, recommended external test set, benign-cohort construction, metric definitions, and guarded improvement recommendations.
- `DATASET_OVERLAP.md` — overlap analysis between NPMAnalysis and external candidates.

## Baseline source (preserved)

- Decisions: `analysis/2026-11-04-npmanalysis-accuracy/output/check-results.cli.jsonl`
- Aggregate metrics: `analysis/2026-11-04-npmanalysis-accuracy/output/metrics.cli.json`
- Rebuilt case list: `analysis/2026-11-04-npmanalysis-accuracy/output/npmanalysis_cases.rebuilt.csv` (13,708 rows)
- Root-cause artifacts: `analysis/2026-11-04-npmanalysis-accuracy/output/root_cause_summary.md`, `improvement-scope-and-recommendations.txt`, `malicious_allow_analysis.csv`, `benign_block_analysis.csv`
- Engine state: `trust_engine_version=rule_v1`, commit `a4a4d5d` (`src/constants.js`, `src/utils.js`, `src/feature-extractor.js`, `src/trust-engine.js`, `src/decision-engine.js`, `src/orchestrator.js`).

## Key baseline facts (must be preserved when comparing)

- End-to-end (BLOCK positive): Acc 97.09%, Prec 97.63%, Rec 96.12%, Spec 97.94%, F1 0.9687, MCC 0.9416 (TP 6171, FP 150, TN 7138, FN 249).
- Headline is dominated by registry-existence short-circuits: 6,040/6,171 malicious blocks were `nonexistent_package/version`; only 131 existing malicious packages were blocked (all `blocked: known_malicious` via OSV). 249 existing malicious packages were missed (235 ALLOW, 14 WARN). 150 benign BLOCKs were all existence failures.
- Existing-packages subset (7,518): BLOCK-positive recall 34.47% (131/380) with 0 FP; BLOCK-or-WARN recall 38.16% (145/380) with 35 FP.
- **Risk-scoring stage only** (existing, excluding OSV-known-malicious short-circuit; 7,387 cases): BLOCK-positive recall 0% (0/249 malicious caught, 0 FP) — current rule score produced no BLOCKs; BLOCK-or-WARN recall 5.62% (14/249) at 35 benign FPs. This is the primary gap for weight/feature improvements.
- `pact-decision-engine.jsonl` in repo root contains only recent manual runs (not the 13,708 baseline); per-case feature vectors for the 2026-11-04 run are not preserved beyond `check-results.cli.jsonl` fields. Future runs must log full evidence.

