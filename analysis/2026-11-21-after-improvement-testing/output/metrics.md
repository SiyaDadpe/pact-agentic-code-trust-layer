# PACT check accuracy on Amalfi after-improvement test

Cases: **1114** (benign **656**, malicious **458**)

## Primary metrics

Positive decisions: **BLOCK**

| Metric | All cases | Covered cases (UNKNOWN excluded) |
| --- | ---: | ---: |
| Accuracy | 92.28% | 92.36% |
| Precision | 84.44% | 84.44% |
| Recall | 99.56% | 99.78% |
| Specificity | 87.20% | 87.18% |
| F1 | 0.9138 | 0.9147 |
| Balanced accuracy | 93.38% | 93.48% |
| MCC | 0.8542 | 0.8560 |
| NPV | 99.65% | 99.83% |
| False positive rate | 12.80% | 12.82% |
| False negative rate | 0.44% | 0.22% |

Coverage: **99.82%**; UNKNOWN excluded: **2**

### Confusion matrix

| Actual | Predicted positive | Predicted negative |
| --- | ---: | ---: |
| Malicious | 456 (TP) | 2 (FN) |
| Benign | 84 (FP) | 572 (TN) |

## WARN treated as positive

Positive decisions: **BLOCK, WARN**

| Metric | All cases | Covered cases (UNKNOWN excluded) |
| --- | ---: | ---: |
| Accuracy | 90.48% | 90.56% |
| Precision | 81.43% | 81.43% |
| Recall | 99.56% | 99.78% |
| Specificity | 84.15% | 84.12% |
| F1 | 0.8959 | 0.8968 |
| Balanced accuracy | 91.85% | 91.95% |
| MCC | 0.8238 | 0.8256 |

## Decision distribution

| Label | ALLOW | WARN | BLOCK | UNKNOWN | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| benign | 551 | 20 | 84 | 1 | 656 |
| malicious | 1 | 0 | 456 | 1 | 458 |
| overall | 552 | 20 | 540 | 2 | 1114 |

