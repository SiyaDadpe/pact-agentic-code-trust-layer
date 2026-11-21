// Metrics for the after-improvement test. Headline metrics come from the original
// evaluate-check.mjs (--metrics-only) so they match the first analysis exactly; this adds
// stage-separated views, per-stratum tables, and false-positive / false-negative lists.
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
const ROOT = new URL('../../..', import.meta.url).pathname;
const B = ROOT + 'analysis/2026-11-21-after-improvement-testing/';
const O = B + 'output/';
const cases = fs.readFileSync(B + 'data/amalfi_test.csv', 'utf8').trim().split('\n').slice(1).map((l) => l.split(','));
const stratumOf = new Map(cases.map((c) => [`${c[0]}@${c[1]}`, c[3]]));
const results = fs.readFileSync(O + 'amalfi_results.jsonl', 'utf8').trim().split('\n').map((l) => JSON.parse(l));

// Adapt to the original script's input shape (it keys rows by source_path).
fs.writeFileSync(O + 'eval_cases.csv', ['package_name,package_version,label,source_path', ...cases.map((c) => `${c[0]},${c[1]},${c[2]},${c[0]}@${c[1]}`)].join('\n') + '\n');
fs.writeFileSync(O + 'eval_results.jsonl', results.map((r) => JSON.stringify({ ...r, source_path: r.spec })).join('\n') + '\n');
execFileSync('node', [ROOT + 'analysis/2026-11-04-npmanalysis-accuracy/scripts/evaluate-check.mjs', '--metrics-only',
  '--csv', O + 'eval_cases.csv', '--results', O + 'eval_results.jsonl', '--metrics-json', O + 'metrics.json', '--metrics-md', O + 'metrics.md'], { stdio: 'inherit' });

const isPos = (d, warn) => d === 'BLOCK' || (warn && d === 'WARN');
function m(rows, warn) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const r of rows) { const p = isPos(r.decision, warn); if (r.label === 'malicious') p ? tp++ : fn++; else p ? fp++ : tn++; }
  const n = tp + fp + tn + fn, rec = tp / (tp + fn), spec = tn / (tn + fp), prec = tp + fp ? tp / (tp + fp) : NaN;
  const den = Math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
  return { n, tp, fp, tn, fn, acc: (tp + tn) / n, prec, rec, spec, f1: 2 * prec * rec / (prec + rec), bal: (rec + spec) / 2, mcc: den ? (tp * tn - fp * fn) / den : NaN };
}
const pct = (x) => (Number.isFinite(x) ? (x * 100).toFixed(2) + '%' : 'n/a');
const f4 = (x) => (Number.isFinite(x) ? x.toFixed(4) : 'n/a');
const H = '| View | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | Bal. acc | F1 | MCC |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|';
const row = (name, x) => `| ${name} | ${x.n} | ${x.tp} | ${x.fp} | ${x.tn} | ${x.fn} | ${pct(x.acc)} | ${pct(x.prec)} | ${pct(x.rec)} | ${pct(x.spec)} | ${pct(x.bal)} | ${f4(x.f1)} | ${f4(x.mcc)} |`;
const stage = (r) => r.existence_status !== 'exists' ? `existence:${r.existence_status}` : r.osv_malicious ? 'osv_known_malicious' : r.decision === 'UNKNOWN' ? 'unknown' : 'scoring';
const ruleOf = (r) => r.policy_rule ?? String(r.reason ?? '').split(':')[0];
const tally = (rows, f) => rows.reduce((t, r) => { const k = f(r); t[k] = (t[k] ?? 0) + 1; return t; }, {});
const table = (t, h) => [`| ${h} | count |`, '|---|---:|', ...Object.entries(t).sort((a, b) => b[1] - a[1]).map(([k, v]) => `| ${k} | ${v} |`)].join('\n');

const exists = results.filter((r) => r.existence_status === 'exists');
const scoring = results.filter((r) => stage(r) === 'scoring');
const strata = [...new Set(results.map((r) => stratumOf.get(r.spec)))];
const out = ['# After-improvement test: Amalfi (ICSE \'22) labelled packages', ''];
const freeze = JSON.parse(fs.readFileSync(B + 'data/FREEZE.json', 'utf8'));
out.push(`- PACT code commit: \`${fs.readFileSync(O + 'code_commit.txt', 'utf8').trim()}\`; case list sha256 \`${freeze.case_list_sha256}\``);
out.push(`- Cases: ${results.length} (benign ${results.filter((r) => r.label === 'benign').length}, malicious ${results.filter((r) => r.label === 'malicious').length}); errors: ${results.filter((r) => r.error).length}; UNKNOWN: ${results.filter((r) => r.decision === 'UNKNOWN').length}`);
out.push('- Full metrics in the same format as the first analysis: `output/metrics.md`', '');
out.push('## Stage views', '', '### BLOCK positive', '', H,
  row('C: end-to-end', m(results, false)), row('B1: package/version exists', m(exists, false)), row('B2: scoring stage', m(scoring, false)),
  ...strata.map((s) => row(`C: ${s}`, m(results.filter((r) => stratumOf.get(r.spec) === s), false))), '');
out.push('### BLOCK or WARN positive', '', H,
  row('C: end-to-end', m(results, true)), row('B1: package/version exists', m(exists, true)), row('B2: scoring stage', m(scoring, true)),
  ...strata.map((s) => row(`C: ${s}`, m(results.filter((r) => stratumOf.get(r.spec) === s), true))), '');
out.push('## Where decisions came from', '', table(tally(results, (r) => `${r.label} | ${stage(r)} | ${r.decision}`), 'label | stage | decision'), '');
out.push('## Scoring-stage rules fired', '', table(tally(scoring.filter((r) => r.decision !== 'ALLOW'), (r) => `${r.label} | ${r.decision} | ${ruleOf(r)}`), 'label | decision | rule'), '');

const csvOut = (rows) => ['spec,label,stratum,stage,decision,rule,risk_score,weekly_downloads,install_scripts',
  ...rows.map((r) => [r.spec, r.label, stratumOf.get(r.spec), stage(r), r.decision, ruleOf(r), r.risk_score,
    r.evidence?.downloads?.weekly ?? '', JSON.stringify(Object.fromEntries(Object.entries(r.lifecycle_scripts ?? {}).filter(([, v]) => v))).replace(/[",\n]/g, ' ')].join(','))].join('\n') + '\n';
const fps = results.filter((r) => r.label === 'benign' && isPos(r.decision, true));
const fns = results.filter((r) => r.label === 'malicious' && !isPos(r.decision, false));
fs.writeFileSync(O + 'false_positives.csv', csvOut(fps));
fs.writeFileSync(O + 'false_negatives.csv', csvOut(fns));
out.push(`## Errors (lists in output/false_positives.csv, output/false_negatives.csv)`, '',
  table(tally(fps, (r) => `benign ${r.decision} | ${stage(r)} | ${ruleOf(r)}`), 'false positive (BLOCK/WARN)'), '',
  table(tally(fns, (r) => `malicious ${r.decision} | ${stage(r)} | ${r.decision === 'ALLOW' ? (Object.values(r.lifecycle_scripts ?? {}).some(Boolean) ? 'has install script' : 'no install script') : ruleOf(r)}`), 'false negative (not BLOCK)'), '');
fs.writeFileSync(B + 'REPORT.md', out.join('\n'));
console.log(out.join('\n'));
