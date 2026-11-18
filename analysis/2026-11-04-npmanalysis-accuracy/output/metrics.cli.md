# PACT check accuracy on NPMAnalysis

Cases: **13708** (benign **7288**, malicious **6420**)

## Primary metrics

Positive decisions: **BLOCK**

| Metric | All cases | Covered cases (UNKNOWN excluded) |
| --- | ---: | ---: |
| Accuracy | 97.09% | 97.09% |
| Precision | 97.63% | 97.63% |
| Recall | 96.12% | 96.12% |
| Specificity | 97.94% | 97.94% |
| F1 | 0.9687 | 0.9687 |
| Balanced accuracy | 97.03% | 97.03% |
| MCC | 0.9416 | 0.9416 |
| NPV | 96.63% | 96.63% |
| False positive rate | 2.06% | 2.06% |
| False negative rate | 3.88% | 3.88% |

Coverage: **100.00%**; UNKNOWN excluded: **0**

### Confusion matrix

| Actual | Predicted positive | Predicted negative |
| --- | ---: | ---: |
| Malicious | 6171 (TP) | 249 (FN) |
| Benign | 150 (FP) | 7138 (TN) |

## WARN treated as positive

Positive decisions: **BLOCK, WARN**

| Metric | All cases | Covered cases (UNKNOWN excluded) |
| --- | ---: | ---: |
| Accuracy | 96.94% | 96.94% |
| Precision | 97.10% | 97.10% |
| Recall | 96.34% | 96.34% |
| Specificity | 97.46% | 97.46% |
| F1 | 0.9672 | 0.9672 |
| Balanced accuracy | 96.90% | 96.90% |
| MCC | 0.9385 | 0.9385 |

## Decision distribution

| Label | ALLOW | WARN | BLOCK | UNKNOWN | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| benign | 7103 | 35 | 150 | 0 | 7288 |
| malicious | 235 | 14 | 6171 | 0 | 6420 |
| overall | 7338 | 49 | 6321 | 0 | 13708 |

