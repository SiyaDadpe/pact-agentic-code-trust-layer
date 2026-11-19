# PACT evaluation plan and protocol (2026-11-19)

**Status:** protocol/report-first. **No production code, weights, thresholds, or dataset labels were modified.** Original baseline outputs remain in `analysis/2026-11-04-npmanalysis-accuracy/output/` unchanged.

## 1. Goals and non-goals

- Establish a reproducible protocol to compare future iterations against the frozen NPMAnalysis baseline.
- Prevent data leakage (package-level) between development/tuning and validation.
- Evaluate on an independent external test set never seen during tuning.
- Report metrics separately for registry-existence checks, risk scoring on existing packages, and end-to-end behavior.
- Non-goals (this phase): changing `src/` production logic, changing `TRUST_ENGINE_WEIGHTS`/`POLICY_THRESHOLDS`, relabeling datasets, installing/executing any package samples.

## 2. Baseline preservation and reproducibility

**Frozen references (do not overwrite):**
- `analysis/2026-11-04-npmanalysis-accuracy/output/check-results.cli.jsonl`
- `analysis/2026-11-04-npmanalysis-accuracy/output/metrics.cli.json` and `metrics.cli.md`
- `analysis/2026-11-04-npmanalysis-accuracy/output/npmanalysis_cases.rebuilt.csv`
- Root-cause artifacts: `root_cause_summary.{md,json}`, `improvement-scope-and-recommendations.txt`, `false-positives.csv`, `false-negatives.csv`, `malicious_allow_analysis.csv`, `benign_block_analysis.csv`
- Protocol snapshot: `analysis/2026-11-19-evaluation-protocol/output/baseline_metrics.{json,md}`

**Environment/config to record per run:** git commit, Node/npm versions, `trust_engine_version`, `src/constants.js` (`TRUST_ENGINE_WEIGHTS`, `POLICY_THRESHOLDS`, `PACKAGE_AGE_THRESHOLD_DAYS`, endpoints/TTLs), `src/utils.js` `isSuspiciousScript`, corpus files (`data/*.json`) hashes, evaluator mode/flags/concurrency/timeout, run timestamp, registry/OSV availability behavior, and log file path. Store full per-case decision records including `feature_vector`, `featureAvailability`/unavailable features, `evidence_completeness`, `existence_check`, `osv_result`, `risk_score`, `confidence`, `decision`, `reason`, `contributing_signals`, and raw/snapshot metadata needed to audit scripts/timestamps/history (current baseline log lacked full per-case snapshots in repo-root log).

**Comparison rule:** future results must be compared on identical case sets/splits using identical metric definitions below; any re-run of NPMAnalysis is a *new measurement* (live registry/OSV drift) and must be labeled with date and delta from frozen baseline.

## 3. NPMAnalysis package-grouped dev/validation splits

**Artifact:** `data/npmanalysis_package_splits.csv` (per-case `split`, `package_stratum`), `data/split_summary.json`.

**Method:**
- Unit of grouping: `package_name` (all `package_name@version` cases for a package remain in the same split). Prevents version-level leakage.
- Stratification: package label stratum (`benign`, `malicious`, `mixed` where a name appears with multiple labels).
- Ratio/seed: 70% dev / 30% val packages per stratum, deterministic shuffle seed `20261119`.
- Mixed-label handling: `mediaspace` (benign 1.4.0, malicious 1.0.0) assigned to `dev` as `mixed`; flagged for manual review and exclusion from automated tuning targets if label ambiguity matters.

| Split | Packages | Cases | Benign cases | Malicious cases |
|---|---:|---:|---:|---:|
| dev | 8,102 | 9,578 | 5,102 | 4,476 |
| val | 3,471 | 4,130 | 2,186 | 1,944 |
| **overlap** | **0** |  |  |  |

**Usage protocol:**
- `dev`: error analysis, feature/ablation experiments, candidate weight/threshold search *only in experiments* (not applied to production in this phase), and script/fixture development.
- `val`: single held-out check for selected candidates after dev tuning; do not iterate on `val` metrics. If `val` is used more than once for decisions, treat it as contaminated and require a fresh holdout.
- Report metrics on `dev`, `val`, and `all` (all = frozen baseline reference) separately.

## 4. External evaluation candidates (investigated)

See `DATASET_OVERLAP.md` for full details and overlap counts.

| Candidate | Availability | License | npm IDs/versions | Labels | Overlap w/ NPMAnalysis | Suitability now |
|---|---|---|---|---|---|---|
| **DataDog malicious-software-packages-dataset** | Public GitHub, actively maintained, npm `manifest.json` + encrypted samples | Apache-2.0 | Names + version semantics (`null` all-version malicious intent; compromised version lists) | Malicious only (intent/compromised) | 946/4,286 malicious names, 1,374/6,420 malicious pairs covered; **377 benign NPMAnalysis pairs conflict** with DD all-version names | **Best available malicious source** for a disjoint external malicious set, after strict exclusion/adjudication; needs benign cohort |
| **MalwareBench (MSR 2024, Zenodo 10573494)** | Public metadata/sample CSVs only; full dataset access on request | CC BY 4.0 (Zenodo record/samples); full-access terms TBD | npm+PyPI name/version/label/metadata in full set (npm subset substantial) | Malware + Neutral | Sample shows 23-name overlap; full unknown (incorporates DD/other sources) | **Secondary/pending access**; strong schema but not immediately usable or provably independent |
| OSV MAL / OpenSSF malicious-packages | Public feeds | Varies/open | Advisory/package/version | Malicious/advisory | Circular with PACT OSV check if naive | Cross-check only, time/usage-scoped |

## 5. Recommended independent external test dataset and benign cohort

### 5.1 Recommendation

**Recommended (immediately actionable): a newly curated, frozen “PACT External npm Test v1” composed of:**
1. **Malicious split:** sampled from **DataDog npm manifest** entries (pinned to a specific commit/SHA/date), restricted to entries with **zero NPMAnalysis package-name overlap** (and pair overlap) and not present in dev/val tuning artifacts; include a stratified mix of `malicious_intent` (`null`) and `compromised` (explicit version) cases. For `null` entries, select a concrete version identifier according to a predeclared rule (e.g., latest version known at snapshot time, or a version evidenced by a corresponding sample path if available) and record the rule—do not treat “all versions” as an unversioned label in scoring.
2. **Benign split:** an independently constructed cohort (DataDog has none), built and frozen before any tuning against it.

MalwareBench full npm subset should be added as **External Test v2** only after access is granted and a full NPMAnalysis/DataDog provenance-overlap audit is completed.

### 5.2 Malicious cohort construction (DataDog-derived)

- Exclude: all NPMAnalysis `package_name` values (both labels) and all NPMAnalysis `name@version` pairs; exclude names in PACT allowlist/corpora-tuning fixtures if used; exclude any case whose label conflicts with trusted intel.
- Stratify: scoped vs unscoped, name-pattern families (typosquat-like, random, brand-jacking) where inferable, compromised vs malicious-intent, and time/source buckets if metadata available.
- Record per case: source repo/commit, manifest entry type, selected version and selection rule, category/path if sample exists, fetch date.
- Size: choose a fixed target (e.g., ≥1,000 cases or balanced to benign cohort) with a documented seed; freeze manifest hashes.
- Integrity checks: manual spot-audit of sampled entries; flag/remove entries with ambiguous/contested labels.

### 5.3 Benign cohort construction (required)

Because no candidate provides a ready trusted benign set aligned to PACT’s live `check` behavior, construct benign cases explicitly:

1. **Sampling frame:** established npm packages with strong legitimacy signals (high download/depended-on/popular-maintainer proxies) **and** a stratified slice of ordinary/low-download packages to avoid “only famous packages” bias. Include scoped and unscoped names.
2. **Hard exclusions:** any package name/version in NPMAnalysis (all splits), in DataDog manifest, in OSV malicious/MAL advisories at snapshot time, in known-malware feeds used by project, or matching internal deny/incident lists. Exclude the 16 NPMAnalysis-benign names overlapping DD manifest from any “trusted benign” pool unless manually cleared.
3. **Exact identifiers:** pin `name@exact_version` (and resolved tarball/dist metadata at snapshot). Prefer versions whose source is available and whose lifecycle scripts (if any) are inspectable.
4. **Behavior/feature coverage:** include benign packages with legitimate install/build scripts (e.g., native addons/build steps), multiple dependency profiles, varied ages, and packages with/without provenance to test specificity (avoid a benign set that is trivially “clean”).
5. **Ground-truth confidence:** label `benign` only when registry metadata exists, no malicious intel matches, and (for a reviewed subset) manual/static inspection finds no malicious behavior. Document residual risk—“benign” is a best-effort label.
6. **Snapshotting:** capture npm registry response, OSV response, and PACT decision/log at the same evaluation time; live drift means future re-evals must be re-snapshotted and versioned.
7. **Balance/strata:** target class balance appropriate to the metric view (and always report per-stratum/per-class rates), not only aggregate accuracy.
8. **Freeze:** publish cohort list + hashes + selection seed + snapshot date before tuning; treat as never-seen holdout.

## 6. Metrics design (separated by evaluation stage)

Treat **`BLOCK` as the positive (risky/malicious/actionable-block) prediction for malicious detection** unless stated otherwise; always also report `BLOCK|WARN` as positive. Treat `UNKNOWN` as uncovered/abstain (report separately, do not silently count as ALLOW or BLOCK). For benign cases, a positive prediction is a false positive.

### 6.1 Stage A — Registry-existence / availability checks

*Population:* all requested cases. *Question:* did the pre-risk pipeline correctly resolve package/version existence and handle availability?

| Metric | Definition / reporting |
|---|---|
| Existence resolution accuracy (when ground-truth existence is known) | Correct classification of `exists` vs `nonexistent_package` vs `nonexistent_version` vs `registry_unavailable/unknown`. Primary on datasets with known-existence labels; on NPMAnalysis (live-registry-evaluated) report observed outcomes and reason codes, not “truth” of historical existence. |
| Existence short-circuit counts/rates | `blocked: nonexistent_package`, `blocked: nonexistent_version` by true label and by stage. |
| Benign existence-failure rate | benign cases blocked for existence/unavailability reasons (NPMAnalysis baseline: 150/7,288 = 2.06%, all missing pkg/ver). |
| Malicious existence-block rate | malicious cases blocked for existence reasons (baseline: 6,040/6,420) — **report separately from risk-score detection**. |
| Availability/abstention | `UNKNOWN`/`registry_or_osv_unavailable` count, rate, and by label; coverage = 1 − unknown rate. |

### 6.2 Stage B — Risk-score performance on existing packages (core model quality)

*Population:* cases where `existence_check.status == exists` (and, for “pure scoring”, exclude cases decided by non-score short-circuits such as `blocked: known_malicious` if measuring the rule/ML score itself). *Question:* given analyzable metadata, how well does scoring separate malicious from benign?

Report two subviews:
- **B1 Existing, end-to-end on subset:** includes OSV-known-malicious and policy short-circuits among existing packages (reflects operational protection on resolvable packages).
- **B2 Scoring-stage only:** excludes `blocked: known_malicious` (and any other intel-only terminal blocks) to isolate feature/weight/threshold performance.

| Metric | Definition |
|---|---|
| Confusion matrix | TP/FP/TN/FN for BLOCK+ and for BLOCK|WARN+ |
| Recall (TPR) | TP/(TP+FN) on malicious-in-population |
| Specificity (TNR) | TN/(TN+FP) on benign-in-population; **FPR = 1−TNR** |
| Precision (PPV) | TP/(TP+FP) |
| F1, Balanced accuracy | Harmonic mean P/R; (TPR+TNR)/2 |
| MCC | Matthews correlation coefficient (robust to imbalance) |
| Score/risk distributions | Median/quantiles of `risk_score` by label and by decision; separation/AUROC/AUPRC when continuous scores available for all in population |
| Confidence calibration | Binned confidence vs observed correctness/abstention; ECE if sufficient data |
| Evidence completeness | Mean/quantiles of `evidence_completeness`, unavailable-feature rates, and performance stratified by completeness |

**Baseline reference (frozen):** B1 existing BLOCK+ recall 34.47% (131/380), 0 FP, F1 0.5127. B2 scoring-only BLOCK+ recall 0.00% (0/249 malicious caught by score), BLOCK|WARN recall 5.62% (14/249) with 35 benign FP.

### 6.3 Stage C — End-to-end performance

*Population:* all requested cases (including missing/unavailable as observed). *Question:* what decision would a user/CI receive?

| Metric | Definition |
|---|---|
| Decision confusion matrix | TP/FP/TN/FN overall for BLOCK+ and BLOCK|WARN+ |
| Accuracy, Precision, Recall, Specificity, F1, Balanced accuracy, MCC, NPV, FPR, FNR | Standard definitions over all cases (and over covered cases excluding UNKNOWN) |
| Coverage / abstention | % non-UNKNOWN; UNKNOWN breakdown by reason |
| Reason/action mix | Counts by `reason`/`policy_rule`/existence/osv status and label |
| Stage-attribution | Share of TP/FP/TN/FN attributable to existence, OSV-known-malicious, policy, and score-threshold blocks |

**Baseline reference (frozen):** end-to-end BLOCK+ Acc 97.09%, Prec 97.63%, Rec 96.12%, Spec 97.94%, F1 0.9687, MCC 0.9416, 0 UNKNOWN (13,708 cases). Must be interpreted with stage attribution (existence dominates malicious TPs).

### 6.4 Reporting requirements for every run

- Publish metrics for `all`, `dev`, `val`, and external-holdout sets; and for stages A/B1/B2/C.
- Include confusion matrices, per-label decision counts, coverage, and top reason codes.
- Include stratified slices: scoped/unscoped, has install-time scripts, evidence completeness buckets, OSV available/unavailable, popularity/downloads availability.
- Never report a single headline accuracy without stage attribution on NPMAnalysis-like data.

## 7. Guarded improvement backlog (evaluate on `dev` only; do not apply to production yet)

Prioritized by baseline root causes (235 malicious ALLOW on existing packages; 116 with install-time scripts but `lifecycle_script_risk==0`; 90 with high behavior features but score ≤0.2605; missing evidence scored as zero):

1. **Lifecycle script detection (high impact, low-risk to prototype):** replace/extend `isSuspiciousScript` to catch direct execution patterns observed in misses (`node <file>`, `node *.cjs/.js` in install hooks, `./pre.sh`, `sh/bash <path>`, chained shell) while explicitly allowlisting/discounting standard benign build invocations (`node-gyp rebuild`, common `prepare/build`-only patterns) to limit FP. Distinguish install-time (`preinstall/install/postinstall/prepare`) from non-install hooks. *Measure B2 recall and benign WARN/FP on dev before any prod change.*
2. **Scoring under missing evidence (high impact, needs care):** stop treating unavailable features as safe zeros—evaluate renormalization over available weighted features and/or explicit incompleteness penalty/abstention; report effect on B2 and calibration.
3. **Signal combination/threshold calibration (dev-only experiments):** reweight or add bounded combination rules for observed high-signal patterns (e.g., dependency_risk + executable_flag + hallucination/name signals) to cross WARN/BLOCK on dev; validate against val and benign FP budget. Do not lower global BLOCK threshold blindly.
4. **Data/feature completeness:** improve population of downloads, provenance, maintainer/publisher/version-history features and `release_burstiness_risk` (currently computed, unweighted) in experiments; log raw timestamps/history for audit.
5. **Existence-reason hygiene:** keep `nonexistent_*` as distinct A-stage outcomes (already distinct) and never conflate with B-stage maliciousness in model metrics.

Any candidate passing dev gates must be re-evaluated on `val`, then (if adopted) on frozen external holdout, with full metric reports and config hashes.

## 8. Deliverables produced in this protocol pass

- `README.md` (this folder) — index and frozen-baseline summary.
- `EVALUATION_PLAN.md` — protocol, metrics, external-test recommendation, benign-cohort design, backlog.
- `DATASET_OVERLAP.md` — external dataset assessment and NPMAnalysis overlap.
- `data/npmanalysis_package_splits.csv`, `data/split_summary.json` — package-grouped dev/val splits.
- `output/baseline_metrics.json`, `output/baseline_metrics.md` — frozen baseline metrics (all/dev/val, stages A/B/C views).

**Production code/weights/thresholds/labels modified:** none.
