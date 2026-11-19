# Baseline Metrics Snapshot (frozen)

- Source: `analysis/2026-11-04-npmanalysis-accuracy/output/check-results.cli.jsonl` (13,708 cases, 100% coverage, 0 UNKNOWN)
- Engine/config: `trust_engine_version=rule_v1`, weights/thresholds from `src/constants.js` at commit `a4a4d5d`; no production changes made for this protocol.
- Splits: package-grouped 70/30 dev/val (`data/npmanalysis_package_splits.csv`).

## ALL (13708 cases)

Decisions: {'benign:ALLOW': 7103, 'benign:BLOCK': 150, 'benign:WARN': 35, 'malicious:BLOCK': 6171, 'malicious:ALLOW': 235, 'malicious:WARN': 14}

### End-to-end, BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 13708 | 6171 | 150 | 7138 | 249 | 97.09% | 97.63% | 96.12% | 97.94% | 96.87% | 94.16% |

### End-to-end, BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 13708 | 6185 | 185 | 7103 | 235 | 96.94% | 97.10% | 96.34% | 97.46% | 96.72% | 93.85% |

Existing packages subset: n=7518 decisions={'benign:ALLOW': 7103, 'benign:WARN': 35, 'malicious:ALLOW': 235, 'malicious:BLOCK': 131, 'malicious:WARN': 14}

### Existing packages (end-to-end on subset), BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7518 | 131 | 0 | 7138 | 249 | 96.69% | 100.00% | 34.47% | 100.00% | 51.27% | 57.72% |

### Existing packages (end-to-end on subset), BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7518 | 145 | 35 | 7103 | 235 | 96.41% | 80.56% | 38.16% | 99.51% | 51.79% | 53.98% |

Reached scoring stage (existing, excluding OSV-known-malicious short-circuit): n=7387 decisions={'benign:ALLOW': 7103, 'benign:WARN': 35, 'malicious:ALLOW': 235, 'malicious:WARN': 14}

### Risk-scoring stage, BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7387 | 0 | 0 | 7138 | 249 | 96.63% | n/a | 0.00% | 100.00% | n/a | n/a |

### Risk-scoring stage, BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7387 | 14 | 35 | 7103 | 235 | 96.34% | 28.57% | 5.62% | 99.51% | 9.40% | 11.41% |

Registry/existence view: {'malicious_missing_blocked': 6040, 'benign_missing_blocked': 150, 'malicious_existing_blocked': 131, 'benign_existing_blocked': 0, 'malicious_existing_allow_or_warn': 249}

## DEV (9578 cases)

Decisions: {'benign:ALLOW': 4976, 'benign:BLOCK': 105, 'benign:WARN': 21, 'malicious:BLOCK': 4351, 'malicious:ALLOW': 115, 'malicious:WARN': 10}

### End-to-end, BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 9578 | 4351 | 105 | 4997 | 125 | 97.60% | 97.64% | 97.21% | 97.94% | 97.42% | 95.18% |

### End-to-end, BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 9578 | 4361 | 126 | 4976 | 115 | 97.48% | 97.19% | 97.43% | 97.53% | 97.31% | 94.95% |

Existing packages subset: n=5212 decisions={'benign:ALLOW': 4976, 'benign:WARN': 21, 'malicious:ALLOW': 115, 'malicious:BLOCK': 90, 'malicious:WARN': 10}

### Existing packages (end-to-end on subset), BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5212 | 90 | 0 | 4997 | 125 | 97.60% | 100.00% | 41.86% | 100.00% | 59.02% | 63.91% |

### Existing packages (end-to-end on subset), BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5212 | 100 | 21 | 4976 | 115 | 97.39% | 82.64% | 46.51% | 99.58% | 59.52% | 60.87% |

Reached scoring stage (existing, excluding OSV-known-malicious short-circuit): n=5122 decisions={'benign:ALLOW': 4976, 'benign:WARN': 21, 'malicious:ALLOW': 115, 'malicious:WARN': 10}

### Risk-scoring stage, BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5122 | 0 | 0 | 4997 | 125 | 97.56% | n/a | 0.00% | 100.00% | n/a | n/a |

### Risk-scoring stage, BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5122 | 10 | 21 | 4976 | 115 | 97.34% | 32.26% | 8.00% | 99.58% | 12.82% | 15.08% |

Registry/existence view: {'malicious_missing_blocked': 4261, 'benign_missing_blocked': 105, 'malicious_existing_blocked': 90, 'benign_existing_blocked': 0, 'malicious_existing_allow_or_warn': 125}

## VAL (4130 cases)

Decisions: {'benign:ALLOW': 2127, 'benign:WARN': 14, 'benign:BLOCK': 45, 'malicious:BLOCK': 1820, 'malicious:ALLOW': 120, 'malicious:WARN': 4}

### End-to-end, BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4130 | 1820 | 45 | 2141 | 124 | 95.91% | 97.59% | 93.62% | 97.94% | 95.56% | 91.84% |

### End-to-end, BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4130 | 1824 | 59 | 2127 | 120 | 95.67% | 96.87% | 93.83% | 97.30% | 95.32% | 91.33% |

Existing packages subset: n=2306 decisions={'benign:ALLOW': 2127, 'benign:WARN': 14, 'malicious:BLOCK': 41, 'malicious:ALLOW': 120, 'malicious:WARN': 4}

### Existing packages (end-to-end on subset), BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2306 | 41 | 0 | 2141 | 124 | 94.62% | 100.00% | 24.85% | 100.00% | 39.81% | 48.46% |

### Existing packages (end-to-end on subset), BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2306 | 45 | 14 | 2127 | 120 | 94.19% | 76.27% | 27.27% | 99.35% | 40.18% | 43.45% |

Reached scoring stage (existing, excluding OSV-known-malicious short-circuit): n=2265 decisions={'benign:ALLOW': 2127, 'benign:WARN': 14, 'malicious:ALLOW': 120, 'malicious:WARN': 4}

### Risk-scoring stage, BLOCK positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2265 | 0 | 0 | 2141 | 124 | 94.53% | n/a | 0.00% | 100.00% | n/a | n/a |

### Risk-scoring stage, BLOCK or WARN positive

| n | TP | FP | TN | FN | Acc | Prec | Rec | Spec | F1 | MCC |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2265 | 4 | 14 | 2127 | 120 | 94.08% | 22.22% | 3.23% | 99.35% | 5.63% | 6.59% |

Registry/existence view: {'malicious_missing_blocked': 1779, 'benign_missing_blocked': 45, 'malicious_existing_blocked': 41, 'benign_existing_blocked': 0, 'malicious_existing_allow_or_warn': 124}
