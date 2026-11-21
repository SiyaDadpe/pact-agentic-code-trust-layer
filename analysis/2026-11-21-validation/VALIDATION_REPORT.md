# Validation results (one-time check)

- Code commit: `ce8420c`
- Cases: 4130 run, 4130 matched to the frozen baseline. Registry drift (existence changed since 2026-11-04): 0, excluded from the paired comparison.
- Errors: 0; UNKNOWN: 0

## C: end-to-end (paired, drift excluded), BLOCK positive

| Run | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline (2026-11-04) | 4130 | 1820 | 45 | 2141 | 124 | 95.91% | 97.59% | 93.62% | 97.94% | 0.9556 | 0.9184 |
| Current | 4130 | 1830 | 45 | 2141 | 114 | 96.15% | 97.60% | 94.14% | 97.94% | 0.9584 | 0.9231 |

## C: end-to-end (paired, drift excluded), BLOCK or WARN positive

| Run | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline (2026-11-04) | 4130 | 1824 | 59 | 2127 | 120 | 95.67% | 96.87% | 93.83% | 97.30% | 0.9532 | 0.9133 |
| Current | 4130 | 1863 | 72 | 2114 | 81 | 96.30% | 96.28% | 95.83% | 96.71% | 0.9606 | 0.9256 |

## B2: scoring stage (exists, not OSV-malicious), BLOCK positive

| Run | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline (2026-11-04) | 2265 | 0 | 0 | 2141 | 124 | 94.53% | n/a | 0.00% | 100.00% | n/a | n/a |
| Current | 2265 | 10 | 0 | 2141 | 114 | 94.97% | 100.00% | 8.06% | 100.00% | 0.1493 | 0.2767 |

## B2: scoring stage (exists, not OSV-malicious), BLOCK or WARN positive

| Run | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline (2026-11-04) | 2265 | 4 | 14 | 2127 | 120 | 94.08% | 22.22% | 3.23% | 99.35% | 0.0563 | 0.0659 |
| Current | 2265 | 43 | 27 | 2114 | 81 | 95.23% | 61.43% | 34.68% | 98.74% | 0.4433 | 0.4392 |

## B2 excluding fsevents (disputed labels)

| Run | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline, BLOCK | 2265 | 0 | 0 | 2141 | 124 | 94.53% | n/a | 0.00% | 100.00% | n/a | n/a |
| Current, BLOCK | 2265 | 10 | 0 | 2141 | 114 | 94.97% | 100.00% | 8.06% | 100.00% | 0.1493 | 0.2767 |
| Baseline, BLOCK|WARN | 2265 | 4 | 14 | 2127 | 120 | 94.08% | 22.22% | 3.23% | 99.35% | 0.0563 | 0.0659 |
| Current, BLOCK|WARN | 2265 | 43 | 27 | 2114 | 81 | 95.23% | 61.43% | 34.68% | 98.74% | 0.4433 | 0.4392 |

## Scoring-stage policy rules fired

| label:decision:rule | count |
|---|---:|
| benign:WARN:install_script_requires_review | 20 |
| benign:WARN:possible_typosquat_requires_review | 7 |
| malicious:BLOCK:install_script_runs_random_filename | 10 |
| malicious:WARN:install_script_requires_review | 33 |

## Changed scoring-stage decisions (52)

| label | spec | baseline | current | rule |
|---|---|---|---|---|
| benign | `@sencha/ext-modern-theme-material@7.8.0` | ALLOW | WARN | install_script_requires_review |
| benign | `coc-snippets@3.4.3` | ALLOW | WARN | install_script_requires_review |
| benign | `colourspace@0.3.1` | ALLOW | WARN | possible_typosquat_requires_review |
| benign | `contenttype@1.0.2` | ALLOW | WARN | possible_typosquat_requires_review |
| benign | `d3-base@0.0.2` | ALLOW | WARN | possible_typosquat_requires_review |
| benign | `grunt-montage@0.0.7` | ALLOW | WARN | install_script_requires_review |
| benign | `kcolor@0.0.4` | ALLOW | WARN | possible_typosquat_requires_review |
| benign | `node-fork@0.4.2` | ALLOW | WARN | install_script_requires_review |
| benign | `oncloud.vis@1.1.6` | ALLOW | WARN | install_script_requires_review |
| benign | `react-poper@1.1.5` | ALLOW | WARN | possible_typosquat_requires_review |
| benign | `underscorex@0.3.4` | ALLOW | WARN | possible_typosquat_requires_review |
| benign | `usbabynames@2.1.2` | ALLOW | WARN | install_script_requires_review |
| benign | `zotion@1.1.5` | ALLOW | WARN | possible_typosquat_requires_review |
| malicious | `@playsistemico/core@61.33.79` | ALLOW | WARN | install_script_requires_review |
| malicious | `@playsistemico/core@71.33.79` | ALLOW | WARN | install_script_requires_review |
| malicious | `@zxncij2390/wash-care-symbol@1.0.3` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.0` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.11` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.2` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.4` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.5` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.6` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.7` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.8` | ALLOW | WARN | install_script_requires_review |
| malicious | `add-sugar@1.0.9` | ALLOW | WARN | install_script_requires_review |
| malicious | `ancularjs@1.1.2` | ALLOW | WARN | install_script_requires_review |
| malicious | `ancularjs@1.1.4` | ALLOW | WARN | install_script_requires_review |
| malicious | `ancularjs@8.7.6` | ALLOW | WARN | install_script_requires_review |
| malicious | `anoularjs@1.1.2` | ALLOW | WARN | install_script_requires_review |
| malicious | `anoularjs@8.7.6` | ALLOW | WARN | install_script_requires_review |
| malicious | `anoularjs@1.1.4` | ALLOW | WARN | install_script_requires_review |
| malicious | `aygularjs@1.1.2` | ALLOW | WARN | install_script_requires_review |
| malicious | `aygularjs@8.7.6` | ALLOW | WARN | install_script_requires_review |
| malicious | `aygularjs@1.1.4` | ALLOW | WARN | install_script_requires_review |
| malicious | `dependencyconfusion7@1.0.0` | ALLOW | WARN | install_script_requires_review |
| malicious | `e39testing@1.0.0` | ALLOW | WARN | install_script_requires_review |
| malicious | `eth-keycontroler@9.0.0` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `ethblk-tracker@8.1.0` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `ether-multcal@0.2.3` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `ethblock-trackr@8.1.0` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `etherjs-util@7.1.5` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `ethers-multcall@0.2.3` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `ethsg-util@3.0.1` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `httpsearch@1.0.1` | ALLOW | WARN | install_script_requires_review |
| malicious | `jngularjs@1.1.2` | ALLOW | WARN | install_script_requires_review |
| malicious | `jngularjs@1.1.4` | ALLOW | WARN | install_script_requires_review |
| malicious | `jngularjs@8.7.6` | ALLOW | WARN | install_script_requires_review |
| malicious | `qweasdzxc@qweasdzxc.tgz` | ALLOW | WARN | install_script_requires_review |
| malicious | `tysapi@3.0.5` | ALLOW | WARN | install_script_requires_review |
| malicious | `wb3-provider@beta.55` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `web3ibn@4.0.7` | ALLOW | BLOCK | install_script_runs_random_filename |
| malicious | `web3util@4.3.2` | ALLOW | BLOCK | install_script_runs_random_filename |
