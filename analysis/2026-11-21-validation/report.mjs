// Validation report: current results vs the frozen 2026-11-04 baseline on the same val cases.
// Views follow EVALUATION_PLAN.md: A (existence), B2 (scoring stage), C (end-to-end).
import fs from 'node:fs';
const ROOT = new URL('../..', import.meta.url).pathname;
const readJsonl = (p) => fs.readFileSync(ROOT + p, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const current = readJsonl('analysis/2026-11-21-validation/output/val_results.jsonl');
const baselineAll = readJsonl('analysis/2026-11-04-npmanalysis-accuracy/output/check-results.cli.jsonl');
const valSpecs = new Set(current.map((r) => r.spec));
const keyOf = (r) => r.spec ?? `${r.package_name}@${r.package_version}`;
const baseline = new Map(baselineAll.map((r) => [keyOf(r), r]).filter(([k]) => valSpecs.has(k)));

const isPos = (d, warn) => d === 'BLOCK' || (warn && d === 'WARN');
function metrics(rows, decisionOf, warn) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const r of rows) {
    const p = isPos(decisionOf(r), warn);
    if (r.label === 'malicious') p ? tp++ : fn++; else p ? fp++ : tn++;
  }
  const n = tp + fp + tn + fn;
  const rec = tp / (tp + fn), spec = tn / (tn + fp), prec = tp + fp ? tp / (tp + fp) : NaN;
  const f1 = prec + rec ? 2 * prec * rec / (prec + rec) : NaN;
  const mccDen = Math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
  return { n, tp, fp, tn, fn, acc: (tp + tn) / n, prec, rec, spec, f1, mcc: mccDen ? (tp * tn - fp * fn) / mccDen : NaN };
}
const pct = (x) => (Number.isFinite(x) ? (x * 100).toFixed(2) + '%' : 'n/a');
const row = (name, m) => `| ${name} | ${m.n} | ${m.tp} | ${m.fp} | ${m.tn} | ${m.fn} | ${pct(m.acc)} | ${pct(m.prec)} | ${pct(m.rec)} | ${pct(m.spec)} | ${Number.isFinite(m.f1) ? m.f1.toFixed(4) : 'n/a'} | ${Number.isFinite(m.mcc) ? m.mcc.toFixed(4) : 'n/a'} |`;
const header = '| Run | n | TP | FP | TN | FN | Acc | Prec | Recall | Spec | F1 | MCC |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|';

const paired = current.filter((r) => baseline.has(r.spec)).map((r) => ({ ...r, base: baseline.get(r.spec) }));
const baseDecision = (r) => r.base.decision;
const curDecision = (r) => r.decision;
const baseExists = (r) => r.base.existence_status === 'exists';
const curExists = (r) => r.existence_status === 'exists';
const drift = paired.filter((r) => baseExists(r) !== curExists(r));
const stable = paired.filter((r) => baseExists(r) === curExists(r));
const scoringStage = stable.filter((r) => curExists(r) && !r.osv_malicious && !r.base.osv_malicious && r.decision !== 'UNKNOWN');

const out = [];
out.push('# Validation results (one-time check)', '');
out.push(`- Code commit: \`${fs.readFileSync(ROOT + 'analysis/2026-11-21-validation/output/code_commit.txt', 'utf8').trim()}\``);
out.push(`- Cases: ${current.length} run, ${paired.length} matched to the frozen baseline. Registry drift (existence changed since 2026-11-04): ${drift.length}, excluded from the paired comparison.`);
out.push(`- Errors: ${current.filter((r) => r.error).length}; UNKNOWN: ${current.filter((r) => r.decision === 'UNKNOWN').length}`, '');
for (const [title, rows] of [['C: end-to-end (paired, drift excluded)', stable], ['B2: scoring stage (exists, not OSV-malicious)', scoringStage]]) {
  for (const warn of [false, true]) {
    out.push(`## ${title}, ${warn ? 'BLOCK or WARN' : 'BLOCK'} positive`, '', header);
    out.push(row('Baseline (2026-11-04)', metrics(rows, baseDecision, warn)));
    out.push(row('Current', metrics(rows, curDecision, warn)), '');
  }
}
const noFse = scoringStage.filter((r) => r.package_name !== 'fsevents');
out.push('## B2 excluding fsevents (disputed labels)', '', header);
for (const warn of [false, true]) {
  out.push(row(`Baseline, ${warn ? 'BLOCK|WARN' : 'BLOCK'}`, metrics(noFse, baseDecision, warn)));
  out.push(row(`Current, ${warn ? 'BLOCK|WARN' : 'BLOCK'}`, metrics(noFse, curDecision, warn)));
}
out.push('');
const rules = {};
for (const r of scoringStage) if (r.policy_rule) rules[`${r.label}:${r.decision}:${r.policy_rule}`] = (rules[`${r.label}:${r.decision}:${r.policy_rule}`] ?? 0) + 1;
out.push('## Scoring-stage policy rules fired', '', '| label:decision:rule | count |', '|---|---:|', ...Object.entries(rules).sort().map(([k, v]) => `| ${k} | ${v} |`), '');
const flips = scoringStage.filter((r) => r.decision !== r.base.decision);
out.push(`## Changed scoring-stage decisions (${flips.length})`, '', '| label | spec | baseline | current | rule |', '|---|---|---|---|---|', ...flips.map((r) => `| ${r.label} | \`${r.spec}\` | ${r.base.decision} | ${r.decision} | ${r.policy_rule ?? ''} |`), '');
fs.writeFileSync(ROOT + 'analysis/2026-11-21-validation/VALIDATION_REPORT.md', out.join('\n'));
console.log(out.slice(0, 40).join('\n'));
