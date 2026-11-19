<p align="center">
  <img src="docs/pact-banner.svg" alt="PACT — Pre-Install Agentic Code Trust Layer" width="900">
</p>

# PACT — Pre-Install Agentic Code Trust Layer

**An explainable, rule-based trust layer that decides whether code fetched by an AI coding agent is safe to install.**

PACT sits between a developer — or an AI coding agent — and `npm install`. It resolves the requested package, verifies that it actually exists, checks known-malicious advisories, inspects registry metadata and supply-chain signals, and returns a decision with a full evidence trail: `ALLOW`, `WARN`, `BLOCK`, or `UNKNOWN`.

The project was motivated by **slopsquatting**: AI coding agents frequently hallucinate plausible-looking package names, and attackers can register those names to distribute malware. PACT makes the "should I install this?" decision explicit, deterministic, and auditable before any package is fetched onto the host.

## Contents

[Highlights](#highlights) · [Architecture](#architecture) · [Evaluation](#evaluation) · [Quick start](#quick-start) · [Repository layout](#repository-layout) · [Scope and future work](#scope-and-future-work)

---

## Highlights

- **Deterministic and explainable** — a weighted score (`risk = Σ weightᵢ × featureᵢ`) plus a sorted contribution breakdown for every decision.
- **Short-circuit safety rules** — nonexistent packages and OSV-confirmed malicious packages are blocked directly, without relying on the score.
- **Fails closed** — external-service failures produce `UNKNOWN` instead of a silent `ALLOW`.
- **Install gating** — `pact npm install ...` only forwards to the real npm binary when the aggregate decision is `ALLOW`.
- **Isolated execution** — an optional Docker sandbox installs into a private, container-only workspace, keeping the host clean.
- **Evaluated at scale** — **97.09% accuracy / 0.9416 MCC** on a 13,708-case labelled benchmark (see [Evaluation](#evaluation)).

---

## Architecture

```mermaid
flowchart TD
    U[User or AI agent requests npm package] --> C[CLI entrypoint]
    C --> P[Preprocessor: parse, normalize, corpus match]
    P --> R[npm registry connector]
    R --> E{Package and version exist?}
    E -- No --> B1[BLOCK: nonexistent package]
    E -- Yes --> O[OSV connector]
    O --> M{Known malicious?}
    M -- Yes --> B3[BLOCK: known malicious]
    M -- No --> N[Metadata normalizer]
    N --> F[Feature extractor]
    F --> T[Weighted trust engine]
    T --> D[Decision engine + confidence]
    D --> L[JSONL audit log]
    D --> OUT[Decision with explanation]
    OUT --> I{ALLOW?}
    I -- Yes --> NPM[Run real npm install]
    I -- No --> STOP[Stop, install nothing]
```

Each stage is a separate module under `src/`, so the registry connector, scoring model, and decision policy can be replaced independently. The full request flow and per-file responsibilities are documented in [`PROJECT_GUIDE.md`](PROJECT_GUIDE.md).

### Decision model

| Decision | Condition | Meaning |
| --- | --- | --- |
| `ALLOW` | `risk < 0.40` | Proceed with installation. |
| `WARN` | `0.40 ≤ risk < 0.75` | Stop and require human review. |
| `BLOCK` | `risk ≥ 0.75`, or a direct finding | Refuse installation. |
| `UNKNOWN` | Required external check failed | Do not make a silent decision. |

Risk features include hallucination-corpus membership, lifecycle-install scripts, name similarity to popular packages, package/version age, dependency anomalies, provenance regressions, and publisher/maintainer changes. `confidence` is computed separately from `risk`: it reflects evidence completeness and signal agreement, not suspicion level.

---

## Evaluation

The engine was evaluated against the labelled `NPMAnalysis` malware/benign dataset (7,288 benign and 6,420 malicious package records). Dataset trees were independently verified against the upstream SHA before evaluation; no package archives were downloaded or executed. Full methodology, artifacts, and root-cause analysis are in [`analysis/2026-11-04-npmanalysis-accuracy/`](analysis/2026-11-04-npmanalysis-accuracy/).

<p align="center">
  <img src="docs/metrics.svg" alt="PACT detection performance: 97.09% accuracy, 97.63% precision, 96.12% recall, 97.94% specificity, 0.9687 F1, 0.9416 MCC" width="100%">
</p>

| Metric (`BLOCK` positive) | Result |
| --- | ---: |
| Accuracy | **97.09%** |
| Precision | 97.63% |
| Recall | 96.12% |
| Specificity | 97.94% |
| F1 | 0.9687 |
| Balanced accuracy | 97.03% |
| MCC | 0.9416 |
| Coverage | 100.00% |

<p align="center">
  <img src="docs/confusion-matrix.svg" alt="Confusion matrix: 6,171 true positives, 249 false negatives, 150 false positives, 7,138 true negatives" width="100%">
</p>

Analysis of the false negatives found that all 235 malicious `ALLOW` cases existed in the registry but were not flagged by OSV — the main remaining gap is authoritative malicious-package intelligence, not registry availability. All 150 benign false positives were caused by registry existence failures (unpublished packages or versions).

> **Status:** project in progress — accuracy is actively being improved.

---

## Quick start

Requires Node.js 18+.

```bash
npm install
npm test

# Inspect a package without installing it
node ./src/cli.js check react
node ./src/cli.js check lodash express --json

# Gate a real install behind the decision
node ./src/cli.js npm install react
```

The wrapper blocks on `BLOCK`, stops on `WARN`, and only forwards to `npm install` on `ALLOW`. Every decision is appended to `pact-decision-engine.jsonl` with its full evidence record.

A check prints the decision, the risk score, the confidence, and the signals that drove the result:

```text
ALLOW: react
  confidence=0.970 risk=0.020
  reason=ALLOW: version_age_risk=0.020, hallucination_corpus_risk=0.000, lifecycle_script_risk=0.000
Aggregate: ALLOW
```

### Private and local packages

Packages you own can be explicitly trusted. They return `BYPASS`, skip the public npm/OSV checks, and are logged as an explicit user decision — not as a security result.

```bash
node ./src/cli.js allow add @mycompany/internal-sdk
node ./src/cli.js allow list
node ./src/cli.js allow remove @mycompany/internal-sdk
```

The allowlist lives at `~/.config/pact/allowlist.json`; override it with `PACT_ALLOWLIST_FILE`.

### Docker sandbox

To keep the installed package entirely off the host:

```bash
docker build -t pact-sandbox -f sandbox/Dockerfile .
docker run --rm -it -v "$PWD":/app:ro pact-sandbox sh /app/sandbox/entrypoint.sh
```

The entrypoint copies the read-only source into a private `/workspace`, installs an npm wrapper there, and discards the resulting `node_modules` when the container exits.

---

## Repository layout

```text
src/            CLI, orchestrator, connectors, normalization, scoring, decision, logging
data/           Local popular-package and hallucination corpora
test/           Node test suite for preprocessing, scoring, CLI, and reporting
scripts/        Shell npm wrapper used by the gated install path
sandbox/        Dockerfile and isolated entrypoint
analysis/       Dataset verification, evaluator, metrics, and root-cause study
docs/           README diagram and chart assets
PROJECT_GUIDE.md  Full architecture and file-by-file walkthrough
PACT-decision-engine-LLD.pdf  Low-level design document
```

---

## Scope and future work

This implementation intentionally focuses on the deterministic rule-based engine for npm. Deliberate next steps include a PyPI connector, expanded and externally maintained corpora, historical publisher/maintainer analysis, dependency-graph analysis, a pluggable ML trust engine behind the same `score()` interface, and empirical calibration of the confidence heuristic. Current limitations are documented in [`PROJECT_GUIDE.md`](PROJECT_GUIDE.md#9-current-limitations-and-future-work).
