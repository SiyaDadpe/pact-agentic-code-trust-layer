// Offline re-scoring of saved dev scoring-stage cases with the current src/ rules.
// Recomputes the features that step 3 changes (name similarity against the expanded popular corpus,
// random-script-filename signal) from saved evidence, then applies the current trust and decision engines.
import fs from 'node:fs';
import { levenshtein, hasRandomScriptFilename } from '../../../src/utils.js';
import { popularPackages } from '../../../src/corpus.js';
import { TOP_PACKAGE_CORPUS_LIMIT } from '../../../src/constants.js';
import { scoreWithRuleEngine } from '../../../src/trust-engine.js';
import { decidePackageRisk } from '../../../src/decision-engine.js';

const [inPath, outPath] = process.argv.slice(2);
const corpus = popularPackages.slice(0, TOP_PACKAGE_CORPUS_LIMIT);
const rows = fs.readFileSync(inPath, 'utf8').trim().split('\n').map(JSON.parse)
  .filter((r) => r.existence_status === 'exists' && !r.osv_malicious && r.feature_vector);

const nearestCache = new Map();
function nearestPopularDistance(name) {
  const key = name.toLowerCase();
  if (nearestCache.has(key)) return nearestCache.get(key);
  let best = Infinity;
  for (const candidate of corpus) {
    if (Math.abs(candidate.length - key.length) >= best) continue;
    const d = levenshtein(key, candidate);
    if (d < best) best = d;
    if (best === 0) break;
  }
  nearestCache.set(key, best);
  return best;
}

const out = [];
for (const r of rows) {
  const fv = { ...r.feature_vector };
  const d = nearestPopularDistance(r.package_name);
  const baseName = r.package_name.replace(/^@[^/]+\//, '');
  fv.name_similarity_risk = d === 0 ? 0 : Math.max(0, Math.min(1, (1 - d / 4) * (baseName.length < 5 ? 0.5 : 1)));
  if (d === 0) fv.hallucination_corpus_risk = 0;
  fv.random_script_filename_risk = Object.values(r.lifecycle_scripts ?? {}).filter(Boolean).some(hasRandomScriptFilename) ? 1 : 0;
  const availability = { ...r.feature_availability, random_script_filename_risk: true };
  const scored = scoreWithRuleEngine(fv, availability);
  const decision = decidePackageRisk({
    riskScore: scored.value, breakdown: scored.breakdown, completeness: r.evidence_completeness, availability,
    featureVector: fv, weeklyDownloads: r.evidence?.downloads?.weekly ?? null, existenceCheck: { status: 'exists' }, osvResult: { malicious: false }
  });
  out.push({ spec: r.spec, package_name: r.package_name, label: r.label, before: r.decision, after: decision.action, rule: decision.policy_rule ?? null, risk: scored.value, nearest_popular_distance: d });
}
if (outPath) fs.writeFileSync(outPath, out.map((o) => JSON.stringify(o)).join('\n') + '\n');

function report(title, key) {
  const pos = (x) => x === 'BLOCK' || x === 'WARN';
  const stat = (lab, pred) => out.filter((o) => o.label === lab && pred(o[key])).length;
  const B = out.filter((o) => o.label === 'benign').length;
  const M = out.filter((o) => o.label === 'malicious').length;
  const mb = stat('malicious', (x) => x === 'BLOCK'), mbw = stat('malicious', pos);
  const bb = stat('benign', (x) => x === 'BLOCK'), bbw = stat('benign', pos);
  const pkgs = (lab, pred) => new Set(out.filter((o) => o.label === lab && pred(o[key])).map((o) => o.package_name)).size;
  console.log(`${title.padEnd(7)} malicious BLOCK ${mb}/${M} (${(mb / M * 100).toFixed(1)}%), BLOCK|WARN ${mbw}/${M} (${(mbw / M * 100).toFixed(1)}%) | distinct malicious pkgs caught ${pkgs('malicious', pos)} | benign BLOCK ${bb}/${B} (${(bb / B * 100).toFixed(2)}%), BLOCK|WARN ${bbw}/${B} (${(bbw / B * 100).toFixed(2)}%)`);
}
report('before', 'before');
report('after', 'after');
const changed = out.filter((o) => o.before !== o.after);
console.log(`\nchanged decisions: ${changed.length}`);
for (const o of changed) console.log(`  ${o.label.padEnd(9)} ${o.spec.padEnd(42)} ${o.before} -> ${o.after}  ${o.rule ?? ''}  (nearest popular d=${o.nearest_popular_distance})`);
