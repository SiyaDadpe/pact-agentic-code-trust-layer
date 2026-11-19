#!/usr/bin/env node
// Step 2: re-collect full evidence and feature vectors for the dev scoring-stage cases
// with the fixed evidence collection (download retries, per-version maintainer change).
// Read-only against npm/OSV; nothing is installed. Resumable: skips specs already in --out.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzePackageRequest } from '../../../../src/orchestrator.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const arg = (name, fallback) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
};

const csvPath = path.resolve(ROOT, arg('--csv', 'analysis/2026-11-19-evaluation-protocol/step1-lifecycle/data/dev_scoring_cases.csv'));
const outPath = path.resolve(ROOT, arg('--out', 'analysis/2026-11-19-evaluation-protocol/step2-evidence/output/dev_scoring_step2_features.jsonl'));
const concurrency = Math.max(1, Number(arg('--concurrency', '4')));
const timeoutMs = Math.max(1000, Number(arg('--timeout-ms', '15000')));

const [header, ...lines] = fs.readFileSync(csvPath, 'utf8').trim().split(/\r?\n/);
const columns = header.split(',');
const cases = lines.map((line) => Object.fromEntries(line.split(',').map((value, i) => [columns[i], value])));

const done = new Set();
if (fs.existsSync(outPath)) {
  for (const line of fs.readFileSync(outPath, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try { done.add(JSON.parse(line).spec); } catch {}
  }
}
const pending = cases.filter((c) => !done.has(`${c.package_name}@${c.package_version}`));
console.log(`cases=${cases.length} done=${done.size} pending=${pending.length} concurrency=${concurrency}`);

const out = fs.createWriteStream(outPath, { flags: 'a' });
let completed = 0;

async function evaluate(c) {
  const spec = `${c.package_name}@${c.package_version}`;
  const row = { spec, package_name: c.package_name, package_version: c.package_version, label: c.label };
  try {
    const result = await analyzePackageRequest({ spec, ecosystem: 'npm' }, { timeoutMs });
    const log = result.logEntry ?? {};
    Object.assign(row, {
      existence_status: log.existence_check?.status ?? result.existenceCheck?.status ?? null,
      osv_malicious: Boolean(result.osvResult?.malicious),
      osv_unavailable: Boolean(result.osvResult?.unavailable),
      decision: log.decision ?? result.decision?.decision ?? null,
      risk_score: log.risk_score ?? null,
      reason: log.reason ?? null,
      policy_rule: (log.contributing_signals ?? []).find((s) => s.contribution === 1 && !('weight' in s))?.feature_name ?? null,
      feature_vector: result.featureVector ?? null,
      feature_availability: result.featureAvailability ?? null,
      evidence_completeness: log.evidence_completeness ?? null,
      lifecycle_scripts: result.normalizedMetadata?.lifecycle_scripts ?? null,
      evidence: log.evidence ?? null,
      error: null
    });
  } catch (error) {
    row.error = String(error?.message ?? error);
  }
  out.write(`${JSON.stringify(row)}\n`);
  completed += 1;
  if (completed % 100 === 0) console.log(`${new Date().toISOString()} ${completed}/${pending.length}`);
}

let cursor = 0;
await Promise.all(Array.from({ length: concurrency }, async () => {
  while (cursor < pending.length) {
    const c = pending[cursor++];
    await evaluate(c);
  }
}));
out.end();
console.log(`finished ${completed}`);
