# NPMAnalysis dataset verification

Generated: 2026-11-04T07:18:04.789Z

## Folder tree counts

| Folder | Tree SHA | Truncated | Blobs (.tgz) | Entries |
| --- | --- | --- | ---: | ---: |
| zip_benign | f768aece85e03879665634ee1e890bee2c463a9f | false | 7288 | 21864 |
| zip_malware | abd7ef01642c159a50a1a42dca4bca88a7cc42b4 | false | 6420 | 17126 |

## Canonical record counts

Total: **13708** (benign **7288**, malicious **6420**)

Unique package names: **11573** (benign **7288**, malicious **4286**)

Scoped records: **2808** (benign **2261**, malicious **547**); structural parse failures **0**, case-only normalizations **1**.

## Comparison with current CSV

Current CSV: `/Users/siya/Desktop/npmanalysis_cases.csv`

Rows: **8294** (benign **7288**, malicious **1006**).

Missing from current CSV: **5414** (benign **0**, malicious **5414**), covering **3775** unique package names.

Extra CSV rows not found in the GitHub trees: **0**.

Overlapping-row mismatches: package_name **0**, package_version **0**, label **0**, archive_size_bytes **0**.

## Extraction validation

Path/structure issues: **0**

Duplicate source paths: **0**; duplicate package@version records: **0**.

Noncanonical archive file names: **1465** (parsed from folder path, not filename).

Spec round-trip exact: **13678**; case-only differences: **30**; structural failures: **0**.

## Rebuild

Allowed: **true**

Rebuilt CSV: `/Users/siya/Desktop/slopsquatting-mjp/analysis/2026-11-04-npmanalysis-accuracy/output/npmanalysis_cases.rebuilt.csv` with **13708** rows.

