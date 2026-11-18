# Root-cause analysis: malicious ALLOW and benign BLOCK

Generated: 2026-11-04T09:29:05.566Z

## Evidence sources

- Baseline decisions: `/Users/siya/Desktop/slopsquatting-mjp/analysis/2026-11-04-npmanalysis-accuracy/output/check-results.cli.jsonl`
- Full per-case decision records: `/Users/siya/Desktop/slopsquatting-mjp/pact-decision-engine.jsonl` (14947 entries, last record per package@version wins)
- Decision-log joins: malicious 212 exact + 23 normalized fallback (0 ambiguous); benign 115 exact + 35 normalized fallback (3 ambiguous)
- New network requests: **0**

The feature vector contains 14 fields. **13** are weighted in `TRUST_ENGINE_WEIGHTS`; `release_burstiness_risk` is computed but unweighted.

## Malicious ALLOW: primary root causes

| Category | Count | Share |
| --- | ---: | ---: |
| Suspicious behavior not represented by existing features | 132 | 56.17% |
| Scoring/weighting/threshold issue | 90 | 38.30% |
| No malicious metadata signal (standard build script only) | 13 | 5.53% |

| Subcategory | Count | Share |
| --- | ---: | ---: |
| install_time_scripts_present_but_not_flagged | 80 | 34.04% |
| dependency_risk+executable_flag_risk | 44 | 18.72% |
| no_lifecycle_script_and_no_high_feature | 28 | 11.91% |
| dependency_risk | 27 | 11.49% |
| only_non_install_lifecycle_scripts | 24 | 10.21% |
| standard_build_script_only | 13 | 5.53% |
| hallucination_corpus_risk | 6 | 2.55% |
| publisher_changed_risk | 4 | 1.70% |
| executable_flag_risk | 3 | 1.28% |
| hallucination_corpus_risk+name_similarity_risk+executable_flag_risk | 3 | 1.28% |
| hallucination_corpus_risk+dependency_risk | 2 | 0.85% |
| hallucination_corpus_risk+dependency_risk+executable_flag_risk | 1 | 0.43% |

### OSV status

| Status | Count | Share |
| --- | ---: | ---: |
| no_advisory_found | 226 | 96.17% |
| non_malicious_advisories_only | 9 | 3.83% |

### Secondary evidence

| Factor | Count | Share |
| --- | ---: | ---: |
| no_OSV_malicious_advisory | 235 | 100.00% |
| provenance_and_maintainer_history_unavailable | 235 | 100.00% |
| no_OSV_advisory_at_all | 226 | 96.17% |
| downloads_unavailable | 225 | 95.74% |
| lifecycle_scripts_present_but_not_flagged | 207 | 88.09% |
| at_least_4_weighted_feature_families_unavailable | 184 | 78.30% |
| executable_flag_unavailable | 181 | 77.02% |
| install_time_scripts_present_but_not_flagged | 116 | 49.36% |
| script_heuristic_gap_also_present | 90 | 38.30% |
| zero_risk_score | 17 | 7.23% |
| standard_build_script_only | 13 | 5.53% |
| only_non_malicious_OSV_advisories | 9 | 3.83% |
| high_downloads_low_popularity_risk | 5 | 2.13% |
| unweighted_release_burstiness_signal | 1 | 0.43% |

### Feature-level evidence

| Feature | Weight | Nonzero | >=0.5 | Unavailable | Mean value | Mean contribution | Max contribution |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| hallucination_corpus_risk | 0.18 | 184 | 12 | 0 | 0.227 | 0.0408 | 0.1125 |
| lifecycle_script_risk | 0.17 | 0 | 0 | 0 | 0.000 | 0.0000 | 0.0000 |
| name_similarity_risk | 0.14 | 57 | 3 | 0 | 0.064 | 0.0089 | 0.0700 |
| package_age_risk | 0.1 | 0 | 0 | 0 | 0.000 | 0.0000 | 0.0000 |
| dependency_risk | 0.1 | 126 | 74 | 0 | 0.328 | 0.0328 | 0.1000 |
| provenance_regression_risk | 0.08 | 0 | 0 | 235 | 0.000 | 0.0000 | 0.0000 |
| publisher_changed_risk | 0.06 | 4 | 4 | 64 | 0.017 | 0.0010 | 0.0600 |
| maintainer_changed_risk | 0.05 | 0 | 0 | 235 | 0.000 | 0.0000 | 0.0000 |
| executable_flag_risk | 0.03 | 51 | 51 | 181 | 0.217 | 0.0065 | 0.0300 |
| version_age_risk | 0.04 | 0 | 0 | 0 | 0.000 | 0.0000 | 0.0000 |
| unusual_tag_risk | 0.03 | 0 | 0 | 0 | 0.000 | 0.0000 | 0.0000 |
| cve_risk | 0.01 | 9 | 0 | 0 | 0.005 | 0.0000 | 0.0013 |
| popularity_risk | 0.01 | 9 | 5 | 225 | 0.023 | 0.0002 | 0.0092 |

### Lifecycle script coverage

207 of 235 have at least one lifecycle script; 116 have an install-time script (preinstall/install/postinstall/prepare); 15 have only standard build scripts; 0 were flagged by `lifecycle_script_risk`.

| Marker | Count |
| --- | ---: |
| node_path | 158 |
| node_gyp | 15 |
| sh_path | 6 |
| bash_path | 5 |
| rm_rf | 3 |
| curl_or_wget | 2 |
| write_elsewhere | 1 |

| Script name | Count |
| --- | ---: |
| test | 124 |
| preinstall | 62 |
| start | 50 |
| postinstall | 41 |
| install | 15 |
| build | 12 |
| clean | 9 |
| lint | 6 |
| prepublishOnly | 6 |
| serve | 2 |
| release | 2 |
| dev | 2 |

| Most common script text | Count |
| --- | ---: |
| `test: echo "Error: no test specified" && exit 1` | 83 |
| `start: node index.js` | 40 |
| `preinstall: node new.js` | 36 |
| `test: node index.js` | 12 |
| `install: node-gyp rebuild` | 10 |
| `test: export PATH=$PATH:'pwd'/node_nodules/.bin/ && tap ./test` | 8 |
| `clean: node-gyp clean && rm -f fsevents.node` | 7 |
| `preinstall: ./pre.sh` | 6 |
| `test: /bin/bash ./test.sh 2>/dev/null` | 5 |
| `start: node index.cjs` | 4 |
| `test: jest` | 4 |
| `preinstall: node index.js` | 3 |

High behavior feature means a behavior feature value at or above 0.5. The script heuristic flags only a subset of shell/Node execution patterns; install-time examples such as `preinstall: node new.js` and `preinstall: ./pre.sh` were present but scored zero. Non-install scripts such as `test` and `start` are also included in the counts but are less probative on their own.

### Most common feature patterns

| Pattern | Count |
| --- | ---: |
| script=present;high=none;top=hallucination_corpus_risk | 73 |
| script=present;high=dependency_risk;executable_flag_risk;top=dependency_risk | 44 |
| script=present;high=none;top=dependency_risk | 28 |
| script=present;high=dependency_risk;top=dependency_risk | 25 |
| script=absent;high=none;top=hallucination_corpus_risk | 23 |
| script=present;high=none;top=none | 15 |
| script=present;high=hallucination_corpus_risk;top=hallucination_corpus_risk | 6 |
| script=present;high=hallucination_corpus_risk;name_similarity_risk;executable_flag_risk;top=hallucination_corpus_risk | 3 |
| script=present;high=executable_flag_risk;top=dependency_risk | 2 |
| script=present;high=publisher_changed_risk;top=publisher_changed_risk | 2 |
| script=absent;high=none;top=dependency_risk | 2 |
| script=present;high=publisher_changed_risk;top=hallucination_corpus_risk | 2 |
| script=present;high=hallucination_corpus_risk;dependency_risk;top=hallucination_corpus_risk | 2 |
| script=absent;high=none;top=none | 2 |
| script=present;high=dependency_risk;top=hallucination_corpus_risk | 2 |

### Top positive signals

| Signal | Count |
| --- | ---: |
| hallucination_corpus_risk | 111 |
| dependency_risk | 102 |
| none | 17 |
| popularity_risk | 2 |
| publisher_changed_risk | 2 |
| executable_flag_risk | 1 |

### Representative examples

#### Suspicious behavior not represented by existing features :: install_time_scripts_present_but_not_flagged

- `soliidty@0.0.1`: risk 0.1115, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads unavailable, OSV no_advisory_found
- `ancularjs@8.7.6`: risk 0.1025, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads unavailable, OSV no_advisory_found
- `ancularjs@1.1.2`: risk 0.1025, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads unavailable, OSV no_advisory_found

#### Suspicious behavior not represented by existing features :: no_lifecycle_script_and_no_high_feature

- `axelhowe@TXPJlRoOV1gAScrG`: risk 0.0675, top signal hallucination_corpus_risk, high behavior none, scripts absent, downloads unavailable, OSV no_advisory_found
- `axelhowe@VDhwMArs`: risk 0.0675, top signal hallucination_corpus_risk, high behavior none, scripts absent, downloads unavailable, OSV no_advisory_found
- `axelhowe@VSslJhaE`: risk 0.0675, top signal hallucination_corpus_risk, high behavior none, scripts absent, downloads unavailable, OSV no_advisory_found

#### Suspicious behavior not represented by existing features :: only_non_install_lifecycle_scripts

- `subtitles@lib`: risk 0.1095, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads unavailable, OSV no_advisory_found
- `ancularjs@1.0.0`: risk 0.1025, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads unavailable, OSV no_advisory_found
- `nx-vaults@1.0.0`: risk 0.0982, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads 2, OSV no_advisory_found

#### Scoring/weighting/threshold issue :: dependency_risk+executable_flag_risk

- `pandora@doomsday`: risk 0.1975, top signal dependency_risk, high behavior dependency_risk;executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `tysapi@3.0.5`: risk 0.1975, top signal dependency_risk, high behavior dependency_risk;executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `zenapi@1.0.9`: risk 0.1975, top signal dependency_risk, high behavior dependency_risk;executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found

#### Scoring/weighting/threshold issue :: dependency_risk

- `akiraa-wb@2.0.1`: risk 0.1225, top signal dependency_risk, high behavior dependency_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `akiraa-wb@2.0.2`: risk 0.1225, top signal dependency_risk, high behavior dependency_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `akiraa-wb@1.9.5`: risk 0.1225, top signal dependency_risk, high behavior dependency_risk, scripts present, downloads unavailable, OSV no_advisory_found

#### Scoring/weighting/threshold issue :: hallucination_corpus_risk

- `solitdy@0.0.1`: risk 0.1690, top signal hallucination_corpus_risk, high behavior hallucination_corpus_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `solity@0.0.1`: risk 0.1690, top signal hallucination_corpus_risk, high behavior hallucination_corpus_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `razer@xdk`: risk 0.1670, top signal hallucination_corpus_risk, high behavior hallucination_corpus_risk, scripts present, downloads unavailable, OSV no_advisory_found

#### Scoring/weighting/threshold issue :: publisher_changed_risk

- `fsevents@0.3.5`: risk 0.1708, top signal hallucination_corpus_risk, high behavior publisher_changed_risk, scripts present, downloads unavailable, OSV non_malicious_advisories_only
- `fsevents@2.0.0`: risk 0.1275, top signal hallucination_corpus_risk, high behavior publisher_changed_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `apl-viewhost-web@2023.1.0`: risk 0.0600, top signal publisher_changed_risk, high behavior publisher_changed_risk, scripts present, downloads unavailable, OSV no_advisory_found

#### Scoring/weighting/threshold issue :: executable_flag_risk

- `trochilus@0.1.0`: risk 0.1230, top signal dependency_risk, high behavior executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `@zxncij2390/upload-ali-oss@0.1.2`: risk 0.0760, top signal dependency_risk, high behavior executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `p4d-rpi-tools@1.4.7`: risk 0.0300, top signal executable_flag_risk, high behavior executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found

#### Scoring/weighting/threshold issue :: hallucination_corpus_risk+name_similarity_risk+executable_flag_risk

- `avo@1.3.5`: risk 0.2605, top signal hallucination_corpus_risk, high behavior hallucination_corpus_risk;name_similarity_risk;executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `k0s@0.0.5`: risk 0.2125, top signal hallucination_corpus_risk, high behavior hallucination_corpus_risk;name_similarity_risk;executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `k0s@0.0.6`: risk 0.2125, top signal hallucination_corpus_risk, high behavior hallucination_corpus_risk;name_similarity_risk;executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found

#### Scoring/weighting/threshold issue :: hallucination_corpus_risk+dependency_risk

- `ltval@2.3.10`: risk 0.1645, top signal hallucination_corpus_risk, high behavior hallucination_corpus_risk;dependency_risk, scripts present, downloads unavailable, OSV no_advisory_found
- `ltval@2.3.18`: risk 0.1645, top signal hallucination_corpus_risk, high behavior hallucination_corpus_risk;dependency_risk, scripts present, downloads unavailable, OSV no_advisory_found

#### Scoring/weighting/threshold issue :: hallucination_corpus_risk+dependency_risk+executable_flag_risk

- `hardhatjs@2.22.15`: risk 0.2200, top signal dependency_risk, high behavior hallucination_corpus_risk;dependency_risk;executable_flag_risk, scripts present, downloads unavailable, OSV no_advisory_found

#### No malicious metadata signal (standard build script only) :: standard_build_script_only

- `fsevents@0.2.0`: risk 0.1108, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads unavailable, OSV non_malicious_advisories_only
- `fsevents@0.3.0`: risk 0.1108, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads unavailable, OSV non_malicious_advisories_only
- `fsevents@0.3.1`: risk 0.1108, top signal hallucination_corpus_risk, high behavior none, scripts present, downloads unavailable, OSV non_malicious_advisories_only

## Systemic findings and implications

- Missing features are scored as zero risk. Evidence completeness ranged 0.615-0.846 (median 0.692); 184 cases had at least four weighted features unavailable. Completeness affects confidence, not the risk sum.
- No registry or OSV retrieval failure occurred in these 235 cases. OSV returned no malicious advisory for any of them; 226 had no advisories and 9 had only non-malicious advisories.
- The lifecycle script feature is binary and regex-based. 116 cases had install-time scripts, but none were flagged; the flag also does not distinguish standard build scripts from arbitrary execution.
- High feature values were insufficient to reach WARN/BLOCK: 90 cases had at least one behavior feature at or above 0.5, yet the maximum observed risk was 0.2605.
- Popularity is not a credible primary cause: downloads were unavailable for 225 cases, and only 5 had high downloads with low popularity risk. Its weight is 0.01, so its maximum possible contribution is 0.01.
- `release_burstiness_risk` is computed but unweighted; only one case had a nonzero value (0.02).
- Recommended next experiments, without changing production yet: renormalize weights by available evidence, add a missing-evidence penalty, expand install-script detection to arbitrary script paths, and treat standard build scripts separately. Re-evaluate thresholds against high-behavior cases before changing production policy.

## Benign BLOCK

Total: **150**

| Category | Count | Share |
| --- | ---: | ---: |
| Registry existence check false positive | 150 | 100.00% |

| Subcategory | Count | Share |
| --- | ---: | ---: |
| nonexistent_version | 122 | 81.33% |
| nonexistent_package | 28 | 18.67% |

| OSV status | Count | Share |
| --- | ---: | ---: |
| not_checked | 150 | 100.00% |

Case-normalization suspects among benign BLOCK: **7**.

## Limitations

- No source code or package archive was downloaded or analyzed; the root causes are metadata/score-based.
- The snapshot does not preserve exact publish timestamps or version history. Age features are available, but `published_at_snapshot` is null for all 235 and raw history cannot be reconstructed from the baseline output.
- The snapshot does not preserve full maintainer/publisher history; provenance and maintainer-change features are unavailable for all 235.
- "No OSV adversarial advisory found" is based on OSV lookups that completed successfully. It is distinct from an OSV lookup failure; no lookup failures occurred in these 235 cases.
- The 90 scoring/weighting cases have at least one feature at or above 0.5, but metadata alone cannot establish whether that signal was malicious or benign.
- 13 of the 235 have only standard build install scripts (for example node-gyp) and no high behavior feature; metadata alone does not substantiate maliciousness for those cases.

