# Dataset-overlap report: NPMAnalysis vs external candidates (2026-11-19)

## Scope and method

- **Baseline dataset:** NPMAnalysis rebuilt cases `analysis/2026-11-04-npmanalysis-accuracy/output/npmanalysis_cases.rebuilt.csv` (13,708 package-version cases: 7,288 benign, 6,420 malicious; 11,573 unique package names: 7,288 benign-only in name set except 1 mixed, 4,286 malicious; 1 package name `mediaspace` appears with both labels across versions).
- **Overlap definition:** computed locally from preserved NPMAnalysis case list and externally fetched manifests/metadata. No package archives were downloaded or executed. Overlap is reported at **package-name** and **package-name@version** granularity where possible.
- **External artifacts fetched for verification (read-only):**
  - DataDog `malicious-software-packages-dataset` repo metadata/API and `samples/npm/manifest.json` from `main` (fetched 2026-11-19). npm manifest observed: 48,600 entries (46,526 `null` = all versions malicious intent; 2,074 version lists = 5,258 explicit compromised-version entries).
  - MalwareBench Zenodo record `10573494` metadata and public sample file `Package_info.csv` (99 npm rows). Full MalwareBench dataset not publicly downloadable (access upon request per record).

## 1. DataDog Malicious Software Packages Dataset

| Field | Assessment |
|---|---|
| Source | https://github.com/DataDog/malicious-software-packages-dataset (`main`) |
| Availability | **Public/open.** Repo and manifests/samples accessible via GitHub; npm manifest fetch succeeded 2026-11-19. API reported `pushed_at=2026-11-06T08:50:55Z`, `open_issues=9`, Apache-2.0 license. |
| License | **Apache-2.0** (repo `LICENSE`). README notes malicious samples may contain legitimate licensed code from original packages; redistribution must respect NOTICE/attribution terms. |
| npm-specific coverage | **Yes (npm included).** README states ~29,847 malicious packages across npm/PyPI/IDE extensions/AI Skills and counting. npm manifest: 48,600 package-name entries; samples under `samples/npm/{malicious_intent,compromised_lib}/...` as encrypted zips (`infected`). |
| Package/version identifiers | **Manifest provides names; versions depend on entry type.** `manifest.json` maps package name -> `null` (all versions malicious intent) or `[version,...]` (specific compromised versions). Sample paths encode category/package/version/date zip. Not every manifest entry has a sample zip. |
| Labels/semantics | **Malicious only (two subtypes):** `malicious_intent` (manifest `null` => all versions) and compromised versions of benign packages (manifest version list). No benign cohort. Human-triaged per README. |
| Known caveats | Selection bias (mostly GuardDog/ruleset-driven discovery), samples are active malware (do not execute), discovery date != publication date, manifest broader than samples, package-level `null` may be coarse for version-specific evaluation. |

### Overlap with NPMAnalysis (npm manifest vs rebuilt cases)

| Overlap measure | Count | Notes |
|---|---:|---|
| NPMAnalysis malicious cases | 6,420 (4,286 names) |  |
| Malicious names in DD npm manifest | 946 / 4,286 (22.08%) | Exact string match |
| Malicious cases covered by DD manifest | 1,374 / 6,420 (21.40%) | 1,373 via `null` all-version entries; 1 exact compromised-version-list match |
| Malicious cases with no DD name coverage | 5,046 / 6,420 (78.60%) | Candidate pool for DD-derived external-malicious sampling after filtering |
| NPMAnalysis benign cases with direct DD pair/name conflict | 377 / 7,288 (5.17%) | All matched DD entries typed `all_version_malicious_intent` (`null`) for same package name; **label/conflict requires adjudication** |
| Benign unique names overlapping DD manifest | 16 | 3 in DD all-version entries, 13 names appear in DD compromised-version lists (NPMAnalysis benign versions were not the listed compromised versions, but name-level caution warranted) |
| `mediaspace` | both-label package in NPMAnalysis | Benign `1.4.0` and malicious `1.0.0` in NPMAnalysis; DD manifest entry type should be checked before reuse |

Split impact (package-grouped dev/val): dev malicious 4,476 cases / 3,001 names with 968 pair-covered by DD; val malicious 1,944 / 1,285 with 406 pair-covered. External test selection must exclude any NPMAnalysis package name (and pair) regardless of split to avoid leakage.

**Interpretation:** DataDog has substantial but partial overlap with NPMAnalysis malicious names and a non-trivial benign-name conflict surface due to package-level `all versions` semantics. It is suitable as an **external malicious source only after strict NPMAnalysis-name/pair exclusion and conflict review**, and it cannot supply benign labels.

## 2. MalwareBench (MSR 2024)

| Field | Assessment |
|---|---|
| Source | Zahan et al., "MalwareBench: Malware samples are not enough", MSR 2024 (DOI 10.1145/3643991.3644883). Zenodo: https://zenodo.org/records/10573494 (DOI 10.5281/zenodo.10573494). |
| Availability | **Partially public metadata/samples; full dataset access-controlled.** Zenodo provides record + sample files only (`Package_info.csv` 99 rows, `File_info.csv`). Zenodo states full dataset hosted on GitHub and distributed “upon reasonable request based on ethical considerations…”; public `https://github.com/MalwareBench/dataset` not accessible (404 observed 2026-11-19). |
| License | **Zenodo record license: CC BY 4.0** (metadata/samples). Full-dataset redistribution/use terms depend on access agreement/authors; verify before use. |
| npm-specific coverage | **Yes (npm + PyPI in full set).** Paper/record: 20,792 packages total (6,659 malicious) across npm and PyPI. Follow-on usage (e.g. LLM study) reports 14,214 npm packages (3,523 malicious, 10,691 neutral). Sample CSV inspected: 99 npm rows (59 malware, 40 neutral) with identifiers/metadata. |
| Package/version identifiers | **Yes.** Sample/full schema described includes ecosystem, name, version, release type, ground-truth label, and metadata (file counts/sizes/extensions etc.). Suitable for name@version evaluation if full data obtained. |
| Labels/semantics | **Malware vs Neutral** (neutral = no discovered malware; ground truth via Socket AI Scanner + manual inspection/sampling per paper). Not equivalent to “guaranteed benign forever”. |
| Known caveats | Full data not openly downloadable; aggregates prior sources (Backstabber’s Knife, Guo PyPI, Datadog, MALOSS, Socket internal) so **provenance/overlap with public malicious corpora is likely**; neutral labeling heuristic/inspection-based; access latency/ethics review required. |

### Overlap with NPMAnalysis

| Overlap measure | Count | Notes |
|---|---:|---|
| Public sample npm rows | 99 (59 malware, 40 neutral) | From Zenodo `Package_info.csv` |
| Sample name overlap with NPMAnalysis | 23 package names | Indicative only; sample is not representative of full set |
| Full-dataset overlap | **Unknown without access** | Must compute exact name@version and name-level overlap after deduplication if access granted, especially because MalwareBench incorporates DataDog and other common sources |

**Interpretation:** MalwareBench is conceptually strong (malware+neutral, npm identifiers) but **not immediately usable as an independent external test** due to access control and likely source overlap. Treat as a secondary candidate pending access and overlap audit.

## 3. Other candidates (brief)

| Candidate | Availability | License | npm IDs/labels | Fit for PACT `check` external test | Notes |
|---|---|---|---|---|---|
| OpenSSF malicious-packages / OSV MAL entries | Public | Varies (OSV data/open) | Ecosystem/package/version/advisory IDs, malicious classification | Useful as threat-intel cross-check, less as a balanced labeled benchmark | PACT already queries OSV; using OSV-derived sets risks circularity unless time-split and carefully scoped |
| Backstabber’s Knife, MALOSS, Guo datasets (as used by MalwareBench) | Mixed/public research artifacts | Varies | Often npm/PyPI names/versions, malware-focused | Possible sources but heterogeneous schemas and age/overlap concerns | Prefer consolidated, documented, licensed sources; audit overlap |
| DataDog npm samples (beyond manifest) | Public in repo (encrypted zips) | Apache-2.0 | Category/package/version in paths | Can support static-inspection studies, not needed for metadata-only `check` eval | Do not extract/execute in this protocol phase |

## 4. Recommended external evaluation strategy (overlap-aware)

1. **Do not use any external set without a precomputed NPMAnalysis exclusion list** (all `package_name` and `package_name@version` from rebuilt cases, and optionally normalized-name forms).
2. **Preferred immediately-available malicious external source:** DataDog npm manifest entries with no NPMAnalysis name/pair overlap, drawn preferentially from entries not covered by NPMAnalysis and stratified by subtype (all-version malicious intent vs compromised-version) and package naming patterns. Record the DataDog manifest commit/SHA and fetch date for reproducibility.
3. **Required complement:** an independently constructed benign cohort (DataDog provides none) — see `EVALUATION_PLAN.md`.
4. **Secondary (access-gated):** MalwareBench full npm subset if obtained, after full provenance/overlap audit and removal of NPMAnalysis and DataDog-overlapping items as needed.
5. **Freeze and version external test manifests** (hashes, selection seed, exclusion rules) before tuning; never tune weights/thresholds/features on the external holdout.

