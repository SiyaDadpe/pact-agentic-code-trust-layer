# NPMAnalysis 2026-11-04 analysis

This folder is isolated from the existing PACT source. It contains dataset verification, the rebuilt case CSV, and the evaluator for the `pact check` path.

No package archives were downloaded or executed. The evaluator calls the same `analyzePackageRequest` pipeline used by `node ./src/cli.js check`; it never installs anything.

## Dataset source

- Repository: `lxyeternal/NPMAnalysis`
- Ref: `main`
- Folders:
  - `Dataset/zip_benign`
  - `Dataset/zip_malware`

The recursive root tree was not relied on. The `Dataset` tree and each `zip_*` subtree were fetched separately by SHA with `recursive=1`.

## Verification result

| Folder | Tree SHA | Subtree truncated | `.tgz` records |
| --- | --- | --- | ---: |
| `Dataset/zip_benign` | `f768aece85e03879665634ee1e890bee2c463a9f` | false | 7,288 |
| `Dataset/zip_malware` | `abd7ef01642c159a50a1a42dca4bca88a7cc42b4` | false | 6,420 |
| **Total** | | | **13,708** |

Canonical label counts:

- benign: 7,288
- malicious: 6,420
- unique package names: 11,573 (7,288 benign, 4,286 malicious)

Current CSV comparison:

- Old CSV: 8,294 rows (7,288 benign, 1,006 malicious)
- Missing from old CSV: 5,414 records, all malicious, across 3,775 unique package names
- Benign missing: 0
- Extra CSV rows not in the trees: 0
- Name/version/label/size mismatches on overlapping rows: 0

Scoped packages:

- Total: 2,808 (2,261 benign, 547 malicious)
- Structural extraction failures: 0
- Scoped records missing from the old CSV: 0
- One scoped version is case-normalized by the existing parser: `@guptasiddhant/theme-manager-js@1.0.0-ALPHA.2` becomes `...@1.0.0-alpha.2`

Extraction rules used:

- Package name comes from the top-level folder, with `##` converted to `/` for scoped packages.
- Version comes from the second folder segment.
- The archive filename is not trusted. 1,465 malicious archives use noncanonical names such as date prefixes, hashes, or underscore forms.
- 30 records only differ because the existing `parsePackageSpec` lowercases the spec (7 benign, 23 malicious). There were 0 structural parse failures.

## Rebuilt CSV

- Rebuilt: `output/npmanalysis_cases.rebuilt.csv` (13,708 rows)
- Installed at `~/Desktop/npmanalysis_cases.csv`
- Original truncated CSV backed up as `output/npmanalysis_cases.original-truncated.csv`

The rebuilt file preserves the old row order and appends the missing malicious records in GitHub tree order.

## Full check results

Run date: 2026-11-04

- Cases: 13,708 (7,288 benign, 6,420 malicious)
- Coverage: 100% after retrying 1,216 transient `registry_unavailable` results at lower concurrency
- Confusion matrix (`BLOCK` positive): TP 6,171; FP 150; TN 7,138; FN 249

| Metric | Value |
| --- | ---: |
| Accuracy | 97.09% |
| Precision | 97.63% |
| Recall | 96.12% |
| Specificity | 97.94% |
| F1 | 0.9687 |
| Balanced accuracy | 97.03% |
| MCC | 0.9416 |
| NPV | 96.63% |
| False positive rate | 2.06% |
| False negative rate | 3.88% |

If `WARN` is also treated as positive: accuracy 96.94%, precision 97.10%, recall 96.34%, specificity 97.46%, F1 0.9672, MCC 0.9385.

Decision distribution:

| Label | ALLOW | WARN | BLOCK | UNKNOWN | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| benign | 7,103 | 35 | 150 | 0 | 7,288 |
| malicious | 235 | 14 | 6,171 | 0 | 6,420 |

Benign false positives were all registry existence failures: 122 nonexistent versions and 28 nonexistent packages. The 235 malicious false negatives exist in the registry and were not flagged by OSV, so they are the main scoring gap.

Artifacts:

- `output/check-results.cli.jsonl` - one JSON result per case (13,708 unique rows)
- `output/metrics.cli.json` - full metric payload
- `output/metrics.cli.md` - rendered metrics report
- `output/false-positives.csv` - 150 benign packages predicted `BLOCK`
- `output/false-negatives.csv` - 249 malicious packages not predicted `BLOCK`
- `output/full-run.log` and `output/retry-unknown.log` - run logs

## Scripts

Fetch or inspect the GitHub trees:

```bash
node analysis/2026-11-04-npmanalysis-accuracy/scripts/fetch-dataset-trees.mjs
node analysis/2026-11-04-npmanalysis-accuracy/scripts/fetch-dataset-trees.mjs --offline
```

Verify and rebuild:

```bash
node analysis/2026-11-04-npmanalysis-accuracy/scripts/verify-dataset.mjs --write-rebuilt
```

Run the check evaluation (resumable JSONL output):

```bash
node analysis/2026-11-04-npmanalysis-accuracy/scripts/evaluate-check.mjs \
  --mode cli \
  --csv ~/Desktop/npmanalysis_cases.csv \
  --results analysis/2026-11-04-npmanalysis-accuracy/output/check-results.cli.jsonl \
  --metrics-json analysis/2026-11-04-npmanalysis-accuracy/output/metrics.cli.json \
  --metrics-md analysis/2026-11-04-npmanalysis-accuracy/output/metrics.cli.md \
  --concurrency 16 \
  --batch-size 5 \
  --timeout-ms 10000
```

Retry transient `UNKNOWN` cases:

```bash
node analysis/2026-11-04-npmanalysis-accuracy/scripts/evaluate-check.mjs \
  --mode cli \
  --csv ~/Desktop/npmanalysis_cases.csv \
  --results analysis/2026-11-04-npmanalysis-accuracy/output/check-results.cli.jsonl \
  --concurrency 8 \
  --batch-size 5 \
  --timeout-ms 20000 \
  --retry-unknown
```

Recompute metrics from existing results:

```bash
node analysis/2026-11-04-npmanalysis-accuracy/scripts/evaluate-check.mjs \
  --csv ~/Desktop/npmanalysis_cases.csv \
  --results analysis/2026-11-04-npmanalysis-accuracy/output/check-results.cli.jsonl \
  --metrics-json analysis/2026-11-04-npmanalysis-accuracy/output/metrics.cli.json \
  --metrics-md analysis/2026-11-04-npmanalysis-accuracy/output/metrics.cli.md \
  --metrics-only
```

Primary metrics treat `BLOCK` as the positive prediction. `metrics.md` also reports the alternative where `WARN` is treated as positive, plus all-case and UNKNOWN-excluded views.

## Smoke test

`output/smoke-cases.csv` contains 2 benign and 2 malicious rows. The smoke run produced `output/metrics.smoke.md` and confirmed the evaluator works. This sample is not representative of overall accuracy.

## Caveat

The evaluation uses live npm registry and OSV state. Removed packages, unpublished versions, and network failures affect the confusion matrix. `UNKNOWN` results are reported separately, so the all-case and covered-case metrics can be compared.
