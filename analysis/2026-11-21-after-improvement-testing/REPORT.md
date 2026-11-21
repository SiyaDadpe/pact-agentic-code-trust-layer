# After-improvement test: Amalfi (ICSE '22) labelled packages

- PACT code commit: `af940f7`; case list sha256 `74953d41871386f93ba5033fff5e7366b322156833fca9b11de48b5b3b738487`
- Cases: 1114 (benign 656, malicious 458); errors: 0; UNKNOWN: 2
- Full metrics in the same format as the first analysis: `output/metrics.md`

## Stage views

### BLOCK positive

| View | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | Bal. acc | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| C: end-to-end | 1114 | 456 | 84 | 572 | 2 | 92.28% | 84.44% | 99.56% | 87.20% | 93.38% | 0.9138 | 0.8542 |
| B1: package/version exists | 572 | 0 | 0 | 571 | 1 | 99.83% | n/a | 0.00% | 100.00% | 50.00% | n/a | n/a |
| B2: scoring stage | 572 | 0 | 0 | 571 | 1 | 99.83% | n/a | 0.00% | 100.00% | 50.00% | n/a | n/a |
| C: amalfi_daily_triaged | 442 | 95 | 30 | 317 | 0 | 93.21% | 76.00% | 100.00% | 91.35% | 95.68% | 0.8636 | 0.8332 |
| C: amalfi_basic_corpus | 672 | 361 | 54 | 255 | 2 | 91.67% | 86.99% | 99.45% | 82.52% | 90.99% | 0.9280 | 0.8406 |

### BLOCK or WARN positive

| View | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | Bal. acc | F1 | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| C: end-to-end | 1114 | 456 | 104 | 552 | 2 | 90.48% | 81.43% | 99.56% | 84.15% | 91.85% | 0.8959 | 0.8238 |
| B1: package/version exists | 572 | 0 | 20 | 551 | 1 | 96.33% | 0.00% | 0.00% | 96.50% | 48.25% | n/a | -0.0080 |
| B2: scoring stage | 572 | 0 | 20 | 551 | 1 | 96.33% | 0.00% | 0.00% | 96.50% | 48.25% | n/a | -0.0080 |
| C: amalfi_daily_triaged | 442 | 95 | 50 | 297 | 0 | 88.69% | 65.52% | 100.00% | 85.59% | 92.80% | 0.7917 | 0.7488 |
| C: amalfi_basic_corpus | 672 | 361 | 54 | 255 | 2 | 91.67% | 86.99% | 99.45% | 82.52% | 90.99% | 0.9280 | 0.8406 |

## Where decisions came from

| label | stage | decision | count |
|---|---:|
| benign | scoring | ALLOW | 551 |
| malicious | existence:missing_version | BLOCK | 456 |
| benign | existence:missing_version | BLOCK | 76 |
| benign | scoring | WARN | 20 |
| benign | existence:missing_package | BLOCK | 8 |
| benign | existence:registry_unavailable | UNKNOWN | 1 |
| malicious | existence:registry_unavailable | UNKNOWN | 1 |
| malicious | scoring | ALLOW | 1 |

## Scoring-stage rules fired

| label | decision | rule | count |
|---|---:|
| benign | WARN | install_script_requires_review | 16 |
| benign | WARN | possible_typosquat_requires_review | 4 |

## Errors (lists in output/false_positives.csv, output/false_negatives.csv)

| false positive (BLOCK/WARN) | count |
|---|---:|
| benign BLOCK | existence:missing_version | nonexistent_version | 76 |
| benign WARN | scoring | install_script_requires_review | 16 |
| benign BLOCK | existence:missing_package | nonexistent_package | 8 |
| benign WARN | scoring | possible_typosquat_requires_review | 4 |

| false negative (not BLOCK) | count |
|---|---:|
| malicious UNKNOWN | existence:registry_unavailable | request_timeout | 1 |
| malicious ALLOW | scoring | no install script | 1 |
## Interpretation

- **Malicious detection is almost entirely the existence check.** 456 of 458 malicious versions (2021) are gone from npm and were blocked as nonexistent. Only one live malicious package reached scoring (`cordova-plugin-china-picker@1.0.9`, no install script, allowed); one timed out (UNKNOWN, install not run). This set cannot measure the scoring stage on malicious packages.
- **All 84 benign BLOCKs are versions or packages that no longer exist on npm** (checked against the registry). `npm install` would fail on them too; they are dataset-age effects, not wrong decisions about real code.
- **Real false alarms are the 20 WARNs**, all in the daily-triaged benign group (packages Amalfi's own detector flagged as suspicious and humans cleared): 20/317 existing = 6.3%. Benign basic-corpus packages that exist: 0/255 warned. 16 of the 20 are install-script warnings, including heavily used packages (`gatsby`, `@strapi/strapi` pre-releases), because the established-package exemption applies only to the BLOCK rules, not to the install-script WARN.
- No legitimate package that exists on npm was blocked.

| View | n | Accuracy (BLOCK) | Accuracy (BLOCK/WARN) |
|---|---:|---:|---:|
| As labelled | 1114 | 92.28% | 90.48% |
| Only versions that still exist on npm | 572 | 99.83% | 96.33% |
