# PACT External npm Test v1 (frozen)

An independent test set built and frozen **before** step-3 tuning. It has not been evaluated, and it must not be used for tuning. Run it once, after all development steps are final.

- Case list: `data/external_test_v1.csv` (1,946 cases: 1,000 malicious, 946 benign)
- Freeze record: `data/FREEZE.json` (seed, case-list SHA-256, DataDog commit and manifest hash, version rules, exclusions)
- Builder: `scripts/build_external_test.mjs` (metadata only; no tarballs downloaded, nothing installed)

## Sources

- **Malicious:** DataDog `malicious-software-packages-dataset`, npm `manifest.json` at commit `72c723b`. 800 malicious-intent packages (evaluated unpinned) and 200 compromised library versions (one listed version each).
- **Benign:** npm search results across 40 topic terms, split into a popular stratum (300) and an ordinary stratum (600), plus 46 legitimate packages whose latest version has an install-time script (for example esbuild, core-js, sqlite3, puppeteer, @swc/core).

## Exclusions

- Every NPMAnalysis package name, from both labels.
- Benign: every DataDog manifest name, and any package with an OSV `MAL-` advisory for its pinned version at snapshot time.

## Reporting

Most DataDog packages have probably been removed from npm and will be blocked as nonexistent. Report results separately for registry-existence blocks and for packages that exist and reach scoring, as defined in `../2026-11-19-evaluation-protocol/EVALUATION_PLAN.md`.
