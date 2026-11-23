// Builds the after-improvement test set from the labelled rows of the Amalfi (ICSE '22) dataset.
// Only rows with analysis = benign | malicious are used; "not triaged" rows have no ground truth.
// Any package name already seen by PACT (NPMAnalysis, DataDog manifest, external test v1) is excluded.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
const ROOT = new URL('../../..', import.meta.url).pathname;
const B = ROOT + 'analysis/2026-11-21-after-improvement-testing/';
const sourceCommit = process.argv[2];
// The test set is frozen: never overwrite it unless explicitly asked.
if (fs.existsSync(B + 'data/FREEZE.json') && !process.argv.includes('--rebuild')) {
  console.error('Amalfi test set is frozen (data/FREEZE.json exists); pass --rebuild to regenerate it');
  process.exit(0);
}

function parseCsv(text) {
  const rows = [];
  for (const line of text.trim().split(/\r?\n/)) {
    const cells = []; let cur = ''; let q = false;
    for (const ch of line) {
      if (ch === '"') q = !q; else if (ch === ',' && !q) { cells.push(cur); cur = ''; } else cur += ch;
    }
    cells.push(cur); rows.push(cells);
  }
  const [h, ...rest] = rows;
  return rest.map((r) => Object.fromEntries(h.map((k, i) => [k, r[i]])));
}
const csvNames = (p) => fs.readFileSync(ROOT + p, 'utf8').trim().split('\n').slice(1).map((l) => l.split(',')[0].toLowerCase());
const seen = new Set([
  ...csvNames('analysis/2026-11-04-npmanalysis-accuracy/output/npmanalysis_cases.rebuilt.csv'),
  ...csvNames('analysis/2026-11-21-external-test/data/external_test_v1.csv'),
  ...Object.keys(JSON.parse(fs.readFileSync(ROOT + 'analysis/2026-11-21-external-test/data/datadog_npm_manifest.json', 'utf8'))).map((n) => n.toLowerCase())
]);

const files = ['basic-corpus', 'july-29', 'july-30', 'july-31', 'august-1', 'august-2', 'august-3', 'august-4'];
const byKey = new Map();
const rawSha = {};
let labelled = 0;
for (const f of files) {
  const text = fs.readFileSync(`${B}data/raw_amalfi/${f}.csv`, 'utf8');
  rawSha[f] = crypto.createHash('sha256').update(text).digest('hex');
  for (const r of parseCsv(text)) {
    if (r.analysis !== 'benign' && r.analysis !== 'malicious') continue;
    labelled++;
    const key = `${r.package.toLowerCase()}@${r.version}`;
    const e = byKey.get(key) ?? { name: r.package.toLowerCase(), version: r.version, labels: new Set(), sources: new Set() };
    e.labels.add(r.analysis); e.sources.add(f); byKey.set(key, e);
  }
}
const conflicts = [...byKey.values()].filter((e) => e.labels.size > 1);
const unique = [...byKey.values()].filter((e) => e.labels.size === 1);
const overlap = unique.filter((e) => seen.has(e.name));
const kept = unique.filter((e) => !seen.has(e.name))
  .map((e) => ({ ...e, label: [...e.labels][0], stratum: e.sources.has('basic-corpus') ? 'amalfi_basic_corpus' : 'amalfi_daily_triaged' }))
  .sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));

const csv = ['package_name,package_version,label,stratum', ...kept.map((e) => `${e.name},${e.version},${e.label},${e.stratum}`)].join('\n') + '\n';
fs.writeFileSync(B + 'data/amalfi_test.csv', csv);
const count = (k) => kept.reduce((m, e) => { const v = e[k]; m[v] = (m[v] ?? 0) + 1; return m; }, {});
const freeze = {
  name: 'PACT After-Improvement Test (Amalfi)',
  frozen_at: new Date().toISOString(),
  source: { repo: 'EvanXiaa/npm-malware-detect', commit: sourceCommit, paper: "Sejfia & Schäfer, 'Practical Automated Detection of Malicious npm Packages', ICSE 2022", raw_file_sha256: rawSha },
  case_list_sha256: crypto.createHash('sha256').update(csv).digest('hex'),
  pact_code_commit: execSync('git rev-parse HEAD', { cwd: ROOT }).toString().trim(),
  rules: {
    rows: 'analysis = benign or malicious only; "not triaged" rows excluded',
    versions: 'exact version listed in the dataset (pinned)',
    exclusions: 'names seen in NPMAnalysis, DataDog manifest (72c723b), or external test v1; name@version keys with conflicting labels'
  },
  counts: { labelled_rows: labelled, unique_keys: byKey.size, conflicting_labels: conflicts.length, excluded_seen_names: overlap.length, total: kept.length, by_label: count('label'), by_stratum: count('stratum') }
};
fs.writeFileSync(B + 'data/FREEZE.json', JSON.stringify(freeze, null, 2) + '\n');
console.log(JSON.stringify(freeze.counts, null, 2));
