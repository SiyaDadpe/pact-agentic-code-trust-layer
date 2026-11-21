# Step 3: policy rules and typosquat corpus

Tuned on the dev split only, using the step-2 features (`../2026-11-19-evaluation-protocol/step2-evidence/output/dev_scoring_step2_features.jsonl`). The validation split and the external test set were not used.

## Why weights were not re-fitted

Dev has 124 malicious scoring-stage cases, but only about 60 distinct packages, and several of those are versions of one package or one attacker campaign (12 versions of `akiraa-wb`, 9 `*gularjs` typos, 16 `fsevents` versions). Fitting 13 weights to that would memorize campaigns. Step 3 instead adds a small number of rules derived from how attacks work, and dev is used only to check each rule against a false-alarm budget fixed in advance: at most 1% WARN and 0.1% BLOCK on benign packages.

Signals that do not separate the classes on dev were left unweighted or unchanged. Popularity is inverted on this dataset (benign mean popularity risk 0.763 vs malicious 0.556), executable flag has a likelihood ratio of 1.1, and dependency risk is about 1 below its maximum value.

## Changes

1. **Popular-package corpus:** 91 hand-picked names → 5,000 (the original 91 plus the top of `npm-high-impact` v1.13.0). This uses no labels. On dev it adds no detections, because dev has almost no typosquats of top packages, but typosquats of popular packages are the main slopsquatting threat.
2. **Short-name damping:** names under 5 characters get half the name-similarity value, so a one-letter difference in a very short name is not treated as a typosquat.
3. **BLOCK `install_script_runs_random_filename`:** an install-time execution script runs a machine-generated-looking file (for example `node c0nlywxa.cjs`) in a package with fewer than 10,000 weekly downloads.
4. **BLOCK `typosquat_with_install_script`:** an install-time execution script in a non-established package whose name is one edit from a top package or matches the hallucination corpus.
5. **WARN `possible_typosquat_requires_review`:** a name of 5 or more characters, one edit from a top package, in a non-established package. It is ordered after the existing hallucination BLOCK and WARN rules.

Weights and score thresholds are unchanged.

## Dev results (scoring stage, 4,990 benign / 124 malicious)

| | Before step 3 | After step 3 |
|---|---:|---:|
| Malicious BLOCK | 0 (0.0%) | 18 (14.5%) |
| Malicious BLOCK or WARN | 69 (55.6%) | 69 (55.6%) |
| Benign BLOCK | 0 (0.00%) | 0 (0.00%) |
| Benign BLOCK or WARN | 28 (0.56%) | 43 (0.86%) |

- The 18 new BLOCKs all come from the random-filename rule, mostly one campaign (eth/solidity typosquats with names like `node c0nlywxa.cjs`). Dev cannot show that the rule generalizes; validation and the external test will.
- The 15 new benign WARNs are one-edit look-alikes, several of which merit review (`brcrypt`, `styled-component`, `mocha2`).
- Stability across five package-grouped dev folds: benign BLOCK is 0 in every fold. Benign BLOCK-or-WARN ranges from 0.60% to 1.40%, driven by clusters of related packages such as `iohook` forks. Malicious rates vary widely because each fold has only 13 to 17 malicious cases.

## Label review

- **fsevents (16 dev cases, all labelled malicious):** OSV advisory `MAL-2023-462` (a hijacked binary-download bucket) covers only versions 1.0.0 to 1.2.10. Every dev fsevents version is outside that range (0.x, 1.2.13, 2.0.x), and OSV lists no malware for them. The dataset appears to label the whole package rather than the affected versions. Labels are left unchanged, per the protocol. Excluding fsevents, dev malicious detection is 63.0% BLOCK or WARN and 16.7% BLOCK.
- **mediaspace:** appears with both labels (benign 1.4.0, malicious 1.0.0). It is in dev and has no effect on these results.

## Files

- `scripts/rescore_dev.mjs`: offline re-scoring of saved dev features with the current `src/` rules (no network).
- `scripts/corpus_sim.mjs`: nearest-popular-name distance under different corpus sizes.
- `output/dev_rescored_step3.jsonl`: per-case before and after decisions and triggering rule.
