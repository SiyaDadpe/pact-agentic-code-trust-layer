# PACT check accuracy on NPMAnalysis

Cases: **4** (benign **2**, malicious **2**)

## Primary metrics

Positive decisions: **BLOCK**

| Metric | All cases | Covered cases (UNKNOWN excluded) |
| --- | ---: | ---: |
| Accuracy | 100.00% | 100.00% |
| Precision | 100.00% | 100.00% |
| Recall | 100.00% | 100.00% |
| Specificity | 100.00% | 100.00% |
| F1 | 1.0000 | 1.0000 |
| Balanced accuracy | 100.00% | 100.00% |
| MCC | 1.0000 | 1.0000 |
| NPV | 100.00% | 100.00% |
| False positive rate | 0.00% | 0.00% |
| False negative rate | 0.00% | 0.00% |

Coverage: **100.00%**; UNKNOWN excluded: **0**

### Confusion matrix

| Actual | Predicted positive | Predicted negative |
| --- | ---: | ---: |
| Malicious | 2 (TP) | 0 (FN) |
| Benign | 0 (FP) | 2 (TN) |

## WARN treated as positive

Positive decisions: **BLOCK, WARN**

| Metric | All cases | Covered cases (UNKNOWN excluded) |
| --- | ---: | ---: |
| Accuracy | 100.00% | 100.00% |
| Precision | 100.00% | 100.00% |
| Recall | 100.00% | 100.00% |
| Specificity | 100.00% | 100.00% |
| F1 | 1.0000 | 1.0000 |
| Balanced accuracy | 100.00% | 100.00% |
| MCC | 1.0000 | 1.0000 |

## Decision distribution

| Label | ALLOW | WARN | BLOCK | UNKNOWN | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| benign | 2 | 0 | 0 | 0 | 2 |
| malicious | 0 | 0 | 2 | 0 | 2 |
| overall | 2 | 0 | 2 | 0 | 4 |

