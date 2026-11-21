// Offline: nearest-popular edit distance for dev scoring-stage cases under different popular corpora.
import fs from 'node:fs';
import { levenshtein } from '../../../src/utils.js';
const [featuresPath, topPath] = process.argv.slice(2);
const rows = fs.readFileSync(featuresPath, 'utf8').trim().split('\n').map(JSON.parse)
  .filter((r) => r.existence_status === 'exists' && !r.osv_malicious && r.feature_vector);
const top = JSON.parse(fs.readFileSync(topPath, 'utf8'));
const names = [...new Set(rows.map((r) => r.package_name.toLowerCase()))];
const label = new Map(rows.map((r) => [r.package_name.toLowerCase(), r.label]));
for (const N of [91, 1000, 2000, 5000, 10000]) {
  const corpus = N === 91 ? JSON.parse(fs.readFileSync('data/popular-packages.json', 'utf8')) : top.slice(0, N);
  const stats = { benign: {}, malicious: {} };
  for (const name of names) {
    let best = Infinity;
    for (const c of corpus) { if (Math.abs(c.length - name.length) >= best) continue; const d = levenshtein(name, c); if (d < best) best = d; if (best === 0) break; }
    const bucket = best === 0 ? 'exact' : best <= 2 ? `d${best}` : 'far';
    const lengthOk = name.replace(/^@[^/]+\//, '').length >= 5 ? '' : '_short';
    const key = bucket === 'd1' || bucket === 'd2' ? bucket + lengthOk : bucket;
    stats[label.get(name)][key] = (stats[label.get(name)][key] ?? 0) + 1;
  }
  console.log(`N=${N}`, 'distinct benign pkgs', JSON.stringify(stats.benign), '| distinct malicious pkgs', JSON.stringify(stats.malicious));
}
