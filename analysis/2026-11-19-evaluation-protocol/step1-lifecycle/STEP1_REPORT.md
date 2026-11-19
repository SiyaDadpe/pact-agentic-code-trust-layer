# Step 1 — Lifecycle-script detection (dev scoring stage)

- Generated: 2026-11-19T15:53:06Z
- Branch/workspace: `exp/lifecycle-script-detection-step1` (isolated). **No `src/` code, weights, thresholds, or frozen baseline files changed by this report step; no val split run; no commit.**
- Change under test (already implemented/tested in this workspace): `src/utils.js:isSuspiciousScript` extended to catch direct `node <script>.{js,cjs,mjs,jsx,ts,tsx}` execution in install hooks, `sh|bash <path>` script execution, and direct relative/absolute script-path execution (e.g. `./pre.sh`). Existing signals retained. `node-gyp rebuild` / ordinary build commands not flagged. Install-hook scope unchanged (`preinstall/install/postinstall/prepare` via `metadata-normalizer`/`feature-extractor`).
- Unit tests: `node --test` → **15/15 pass** (includes `test/lifecycle-script-detection.test.js`).

## Scope and comparability

- Population: dev split, **B2 scoring-stage** subset — cases where frozen baseline had `existence_status=exists`, not OSV-known-malicious, and not `UNKNOWN`/unavailable/missing (5,122 cases from `analysis/2026-11-19-evaluation-protocol/step1-lifecycle/data/dev_scoring_cases.csv`, sourced from frozen dev baseline).
- Comparable (same-snapshot simulation, registry still resolvable at re-run): **5117** (4993 benign, 124 malicious). "Before" = old detector logic applied to the step-1 metadata snapshot (`sim_old`); "After" = step-1 detector on same snapshot. This isolates the script-detection change.
- Registry-drift (newly nonexistent package/version at re-run): **5** — **excluded** from before→after comparison (counted separately below).
- Other excluded: **0**.
- Full per-case details: `analysis/2026-11-19-evaluation-protocol/step1-lifecycle/output/dev_scoring_step1_detailed.jsonl` (5,122). Full feature vectors/availability for step-3 weight setting (no new registry calls needed): `analysis/2026-11-19-evaluation-protocol/step1-lifecycle/output/dev_scoring_step1_features.jsonl` (5,122, every case).

## B2 scoring-stage metrics (comparable set, before → after)

### BLOCK positive

| Metric | Before | After |
|---|---:|---:|
| TP | 0 | 0 |
| FP | 0 | 0 |
| TN | 4993 | 4993 |
| FN | 124 | 124 |
| Recall (TPR) | 0.0000% | 0.0000% |
| Specificity (TNR) | 100.0000% | 100.0000% |
| False Positive Rate (FPR) | 0.0000% | 0.0000% |
| Precision (PPV) | n/a | n/a |
| F1 | 0.000000 | 0.000000 |
| MCC | n/a | n/a |
| Balanced accuracy | 50.0000% | 50.0000% |

### BLOCK|WARN positive

| Metric | Before | After |
|---|---:|---:|
| TP | 10 | 69 |
| FP | 21 | 28 |
| TN | 4972 | 4965 |
| FN | 114 | 55 |
| Recall (TPR) | 8.0645% | 55.6452% |
| Specificity (TNR) | 99.5794% | 99.4392% |
| False Positive Rate (FPR) | 0.4206% | 0.5608% |
| Precision (PPV) | 32.2581% | 71.1340% |
| F1 | 0.129032 | 0.624434 |
| MCC | 0.151474 | 0.621130 |
| Balanced accuracy | 53.8220% | 77.5422% |

## Lifecycle-script coverage (`lifecycle_script_risk == 1`)

| Label (comparable) | n | Before | After | Δ |
|---|---:|---:|---:|---:|
| malicious | 124 | 10 | 69 | +59 |
| benign | 4993 | 21 | 28 | +7 |

Notes: coverage is the feature flag used by scoring/policy on install hooks (`preinstall/install/postinstall/prepare`). BLOCK recall unchanged because added detections raise risk by `weight(lifecycle_script_risk)=0.17` but no case crossed the BLOCK threshold/policy with weights/thresholds held fixed; gains appear as WARN (and BLOCK|WARN).

## Newly detected malicious cases (ALLOW → BLOCK|WARN)

Count: **59** (BLOCK: **0**, BLOCK|WARN: **59**).

| spec | before→after | risk before→after | lsr before→after | triggering script text (install hooks) | reason (after) |
|---|---|---:|---:|---|---|
| `@aaakca/myf@1.0.14` | ALLOW→WARN | 0.005097→0.175097 | 0→1 | `preinstall: pwd > /tmp/asda;sh ../../../public/uploads/1.sh > ../../../public/result.txt` | warned: package contains an install-time execution script |
| `@step-security/malware-simulator@0.0.2` | ALLOW→WARN | 0.005313→0.175313 | 0→1 | `preinstall: node compile.js` | warned: package contains an install-time execution script |
| `@step-security/malware-simulator@0.0.3` | ALLOW→WARN | 0.005313→0.175313 | 0→1 | `preinstall: node compile.js` | warned: package contains an install-time execution script |
| `@zxncij2390/upload-ali-oss@0.1.2` | ALLOW→WARN | 0.081733→0.251733 | 0→1 | `postinstall: node ./post-install.cjs` | warned: package contains an install-time execution script |
| `aegularjs@1.1.2` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `aegularjs@1.1.4` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `aegularjs@8.7.6` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `algularjs@1.1.2` | ALLOW→WARN | 0.086051→0.256051 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `algularjs@1.1.4` | ALLOW→WARN | 0.086051→0.256051 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `algularjs@8.7.6` | ALLOW→WARN | 0.086051→0.256051 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `anbularjs@1.1.2` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `anbularjs@1.1.4` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `anbularjs@8.7.6` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `aniularjs@1.1.2` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `aniularjs@1.1.4` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `aniularjs@8.7.6` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `anlularjs@1.1.2` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `anlularjs@1.1.4` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `anlularjs@8.7.6` | ALLOW→WARN | 0.086054→0.256054 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `apgularjs@1.1.2` | ALLOW→WARN | 0.086051→0.256051 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `apgularjs@1.1.4` | ALLOW→WARN | 0.086051→0.256051 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `apgularjs@8.7.6` | ALLOW→WARN | 0.086051→0.256051 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `apl-viewhost-web@2023.1.0` | ALLOW→WARN | 0.066659→0.236659 | 0→1 | `preinstall: node ./scripts/fetch.js` | warned: package contains an install-time execution script |
| `asgularjs@1.1.2` | ALLOW→WARN | 0.086061→0.256061 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `asgularjs@1.1.4` | ALLOW→WARN | 0.086061→0.256061 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `asgularjs@8.7.6` | ALLOW→WARN | 0.086061→0.256061 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `avo@1.3.5` | ALLOW→WARN | 0.232989→0.402989 | 0→1 | `postinstall: ./cli.js track-install` | warned: package contains an install-time execution script |
| `azgularjs@1.1.2` | ALLOW→WARN | 0.080000→0.250000 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `azgularjs@1.1.4` | ALLOW→WARN | 0.080000→0.250000 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `azgularjs@8.7.6` | ALLOW→WARN | 0.080000→0.250000 | 0→1 | `preinstall: node new.js` | warned: package contains an install-time execution script |
| `e39test@1.0.0` | ALLOW→WARN | 0.125000→0.295000 | 0→1 | `postinstall: node index.js` | warned: package contains an install-time execution script |
| `eth-gasreportr@0.2.27` | ALLOW→WARN | 0.062923→0.232923 | 0→1 | `postinstall: node c0nlywxa.cjs` | warned: package contains an install-time execution script |
| `eth-keyringcontrler@9.0.0` | ALLOW→WARN | 0.048286→0.218286 | 0→1 | `postinstall: node saeyrw7c.cjs` | warned: package contains an install-time execution script |
| `eth-tracker@8.1.0` | ALLOW→WARN | 0.054000→0.224000 | 0→1 | `postinstall: node 31kbzord.cjs` | warned: package contains an install-time execution script |
| `ether-js-tx@2.1.2` | ALLOW→WARN | 0.070500→0.240500 | 0→1 | `postinstall: node 3f44du35.cjs` | warned: package contains an install-time execution script |
| `etherscn-api@10.3.0` | ALLOW→WARN | 0.028000→0.198000 | 0→1 | `postinstall: node 2937h0pg.cjs` | warned: package contains an install-time execution script |
| `etherscna-api@10.3.0` | ALLOW→WARN | 0.028000→0.198000 | 0→1 | `postinstall: node wz0wouic.cjs` | warned: package contains an install-time execution script |
| `ethkr-controler@9.0.0` | ALLOW→WARN | 0.048286→0.218286 | 0→1 | `postinstall: node 3rwtagyi.cjs` | warned: package contains an install-time execution script |
| `hardhatjs@2.22.15` | ALLOW→WARN | 0.220000→0.390000 | 0→1 | `postinstall: node rl9c6ze5.cjs` | warned: package contains an install-time execution script |
| `keyring-controller@9.0.0` | ALLOW→WARN | 0.048286→0.218286 | 0→1 | `postinstall: node 4std8qqg.cjs` | warned: package contains an install-time execution script |
| `partner-analytics@9.869.0` | ALLOW→WARN | 0.046000→0.216000 | 0→1 | `preinstall: node build.js` | warned: package contains an install-time execution script |
| `ping-me-maybe@0.0.0` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `preinstall: node index.js` | warned: package contains an install-time execution script |
| `pupeteer-web@0.0.3` | ALLOW→WARN | 0.044000→0.214000 | 0→1 | `postinstall: node 354r952h.cjs` | warned: package contains an install-time execution script |
| `rickroll-on-install@1.0.1` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `postinstall: ./install.sh` | warned: package contains an install-time execution script |
| `solidity-covrage@0.8.13` | ALLOW→WARN | 0.112000→0.282000 | 0→1 | `postinstall: node jcws0y78.cjs` | warned: package contains an install-time execution script |
| `soliidty@0.0.1` | ALLOW→WARN | 0.111500→0.281500 | 0→1 | `postinstall: node yki3qm3t.cjs` | warned: package contains an install-time execution script |
| `solitdy@0.0.1` | ALLOW→WARN | 0.169000→0.339000 | 0→1 | `postinstall: node e22406bu.cjs` | warned: package contains an install-time execution script |
| `solity@0.0.1` | ALLOW→WARN | 0.169000→0.339000 | 0→1 | `postinstall: node s9mgb6t4.cjs` | warned: package contains an install-time execution script |
| `tchap-translations@9.9.11` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `preinstall: ./pre.sh` | warned: package contains an install-time execution script |
| `tchap-translations@9.9.13` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `preinstall: ./pre.sh` | warned: package contains an install-time execution script |
| `tchap-translations@9.9.14` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `preinstall: ./pre.sh` | warned: package contains an install-time execution script |
| `tchap-translations@9.9.15` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `preinstall: ./pre.sh` | warned: package contains an install-time execution script |
| `tchap-translations@9.9.16` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `preinstall: ./pre.sh` | warned: package contains an install-time execution script |
| `tchap-translations@9.9.17` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `preinstall: ./pre.sh` | warned: package contains an install-time execution script |
| `wb3-tokn@1.0.6` | ALLOW→WARN | 0.098556→0.268556 | 0→1 | `postinstall: node n0tsvgi6.cjs` | warned: package contains an install-time execution script |
| `web-eth-abi@4.3.0` | ALLOW→WARN | 0.048286→0.218286 | 0→1 | `postinstall: node wimho03d.cjs` | warned: package contains an install-time execution script |
| `web3e-iban@4.0.7` | ALLOW→WARN | 0.074500→0.244500 | 0→1 | `postinstall: node my3v4tx2.cjs` | warned: package contains an install-time execution script |
| `web3ethabii@4.3.0` | ALLOW→WARN | 0.070786→0.240786 | 0→1 | `postinstall: node pa8cztln.cjs` | warned: package contains an install-time execution script |
| `zenapi@1.0.9` | ALLOW→WARN | 0.197500→0.367500 | 0→1 | `postinstall: node lib/utils/success.js` | warned: package contains an install-time execution script |

## Newly flagged benign cases (regressions, ALLOW → BLOCK|WARN)

Count: **8**.

| spec | before→after | risk before→after | lsr before→after | triggering script text (install hooks) | reason (after) |
|---|---|---:|---:|---|---|
| `@fomobro/forex-analytics-fomo@1.0.13` | ALLOW→WARN | 0.042000→0.212000 | 0→1 | `preinstall: node ./lib/ta-lib/build.js \| postinstall: node-gyp configure && node-gyp build` | warned: package contains an install-time execution script |
| `@the-/util-color@16.1.1` | ALLOW→WARN | 0.042000→0.212000 | 0→1 | `prepare: ../../misc/scripts/pkgSharedInstall.sh;npm run build && npm run doc` | warned: package contains an install-time execution script |
| `@xolvio/fibers@1.0.7` | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `install: node build.js \|\| nodejs build.js` | warned: package contains an install-time execution script |
| `grunt-images@0.2.1` | ALLOW→WARN | 0.008562→0.178562 | 0→1 | `preinstall: ./scripts/install` | warned: package contains an install-time execution script |
| `iobroker.vis-beta@0.14.1` | ALLOW→WARN | 0.042000→0.212000 | 0→1 | `install: node main.js --install --beta` | warned: package contains an install-time execution script |
| `raspi-soft-pwm@6.0.2` | ALLOW→WARN | 0.048000→0.218000 | 0→1 | `preinstall: sh ./script/pigpio.sh` | warned: package contains an install-time execution script |
| `reactive-di-observable@1.0.19` | ALLOW→WARN | 0.046000→0.216000 | 0→1 | `postinstall: test -d conf && conf/resources/postinstall.sh $npm_package_name \|\| exit 0` | warned: package contains an install-time execution script |
| `vstruct@1.7.0` | ALLOW→WARN | 0.126000→0.296000 | 0→1 | `install: node npm/install.mjs` | warned: package contains an install-time execution script |

## Regressions (all)

Count: **8** (malicious detection/severity losses: **0**, benign newly flagged: **8**).

| spec | label | type | before→after | risk before→after | lsr before→after | triggering script text (install hooks) |
|---|---|---|---|---:|---:|---|
| `@fomobro/forex-analytics-fomo@1.0.13` | benign | benign_newly_flagged | ALLOW→WARN | 0.042000→0.212000 | 0→1 | `preinstall: node ./lib/ta-lib/build.js \| postinstall: node-gyp configure && node-gyp build` |
| `@the-/util-color@16.1.1` | benign | benign_newly_flagged | ALLOW→WARN | 0.042000→0.212000 | 0→1 | `prepare: ../../misc/scripts/pkgSharedInstall.sh;npm run build && npm run doc` |
| `@xolvio/fibers@1.0.7` | benign | benign_newly_flagged | ALLOW→WARN | 0.000000→0.170000 | 0→1 | `install: node build.js \|\| nodejs build.js` |
| `grunt-images@0.2.1` | benign | benign_newly_flagged | ALLOW→WARN | 0.008562→0.178562 | 0→1 | `preinstall: ./scripts/install` |
| `iobroker.vis-beta@0.14.1` | benign | benign_newly_flagged | ALLOW→WARN | 0.042000→0.212000 | 0→1 | `install: node main.js --install --beta` |
| `raspi-soft-pwm@6.0.2` | benign | benign_newly_flagged | ALLOW→WARN | 0.048000→0.218000 | 0→1 | `preinstall: sh ./script/pigpio.sh` |
| `reactive-di-observable@1.0.19` | benign | benign_newly_flagged | ALLOW→WARN | 0.046000→0.216000 | 0→1 | `postinstall: test -d conf && conf/resources/postinstall.sh $npm_package_name \|\| exit 0` |
| `vstruct@1.7.0` | benign | benign_newly_flagged | ALLOW→WARN | 0.126000→0.296000 | 0→1 | `install: node npm/install.mjs` |

## Registry-drift cases (excluded from comparison)

Count: **5**. These became nonexistent at re-run time (step 1) but were resolvable in the frozen baseline; excluded from step-1 before→after scoring comparison and reported separately.

| spec | label | frozen existence/decision | step1 existence/decision | step1 reason |
|---|---|---|---|---|
| `correct-calc@1.0.0` | benign | exists/ALLOW | missing_version/BLOCK | blocked: nonexistent_version |
| `dowload_ebok_bread_toast_crumbs_by_alexandra_stafford_31rd1@3.0.0` | benign | exists/ALLOW | missing_version/BLOCK | blocked: nonexistent_version |
| `high-order-function@0.1.3` | benign | exists/ALLOW | missing_version/BLOCK | blocked: nonexistent_version |
| `loggly-light@1.0.1` | benign | exists/ALLOW | missing_version/BLOCK | blocked: nonexistent_version |
| `yummy-bolts@1.4.0` | malicious | exists/ALLOW | missing_version/BLOCK | blocked: nonexistent_version |

## `@sensel/motion@0.0.3` WARN→ALLOW flip (benign, comparable snapshot)

- Frozen baseline: **WARN** (risk 0.2222643455247363, reason: `warned: package contains an install-time execution script`).
- Step-1 snapshot, **old detector logic** (`sim_old`): **WARN** (risk 0.21400000000000002, policy `install_script_requires_review`) with `lifecycle_script_risk=1`.
- Step-1 snapshot, **new detector logic**: **ALLOW** (risk 0.04400000000000001) with `lifecycle_script_risk=0`.
- Install hooks observed: `{"preinstall": null, "install": null, "postinstall": null, "prepare": "svelte-kit sync || echo ''"}` → prepare = `"svelte-kit sync || echo ''"` (other install hooks null).
- Cause: the legacy `isSuspiciousScript` regex treated any `nc` token followed by whitespace as suspicious via the `nc\s` alternative, which **false-matched the substring `nc ` inside `sync `** (`...-kit sy` + `nc ` + `|| ...`). The refined detector no longer has this broad `nc\s` match; it keeps explicit `nc|netcat` as a word token and only flags command-execution contexts. The prepare script is a benign build/sync fallback, so the flip is a **false-positive correction/improvement** (not a malicious regression; it does reduce an install-script warning on this benign package).

## Artifacts

- `analysis/2026-11-19-evaluation-protocol/step1-lifecycle/output/dev_scoring_step1_detailed.jsonl` — per-case before(sim_old)/after(step1) decisions, risks, reasons, full feature vectors, availability, lifecycle scripts, drift status.
- `analysis/2026-11-19-evaluation-protocol/step1-lifecycle/output/dev_scoring_step1_features.jsonl` — **every case** (5,122) with full `feature_vector` (all features) and `feature_availability` for before/after as available, plus identifiers/labels/decisions/lifecycle scripts (designed for step-3 weight setting without new registry calls).
- `analysis/2026-11-19-evaluation-protocol/step1-lifecycle/output/dev_scoring_step1_summary.json` — machine-readable metrics/counts/lists.
- `analysis/2026-11-19-evaluation-protocol/step1-lifecycle/output/dev_scoring_malicious_step1.jsonl` — malicious-subset detailed run (completed earlier).
- Inputs: `analysis/2026-11-19-evaluation-protocol/step1-lifecycle/data/dev_scoring_cases.csv`, `.../output/dev_scoring_frozen.jsonl`.

## Implications for step 3 (weights)

- Step 1 improves B2 BLOCK|WARN recall substantially (+59 malicious cases, 10→69 detected) with a small benign WARN regression (+3) and one benign false-positive correction; BLOCK unchanged under fixed thresholds/weights.
- Use `dev_scoring_step1_features.jsonl` `after.feature_vector` + `after.feature_availability` (and `before` where useful) on **comparable** records only (exclude `comparison_status=registry_drift_nonexistent`) for weight/threshold experiments; keep lifecycle/missing-evidence/other production features unchanged until step 2+ as planned.
