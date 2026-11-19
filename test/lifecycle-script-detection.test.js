import test from 'node:test';
import assert from 'node:assert/strict';
import { isSuspiciousScript } from '../src/utils.js';
import { extractFeatures } from '../src/feature-extractor.js';

const installHookMeta = (script) => ({
  lifecycle_scripts: { preinstall: script },
  dependency_version_ranges: [],
  dependency_count: 0,
  has_bin_entry: false,
  downloads: { weekly: 0, available: true },
  provenance: { present: false },
  provenance_history: []
});

function scriptRiskFor(script) {
  const extracted = extractFeatures({
    metadata: installHookMeta(script),
    request: { resolved_tag: 'pinned', nearest_popular_distance: 8, nearest_hallucination_distance: 8 },
    osvResult: { unavailable: false, knownCveCount: 0, maxSeverity: 0 }
  });
  return extracted.featureVector.lifecycle_script_risk;
}

test('flags requested malicious install-hook script patterns', () => {
  assert.equal(isSuspiciousScript('preinstall: node new.js'), true);
  assert.equal(scriptRiskFor('node new.js'), 1);
  assert.equal(scriptRiskFor('node index.js'), 1);
  assert.equal(scriptRiskFor('./pre.sh'), 1);
  assert.equal(scriptRiskFor('node 3Sk8RYfD.cjs'), 1);
  assert.equal(scriptRiskFor('node AbC123.cjs'), 1);
  assert.equal(scriptRiskFor('sh ../../../public/uploads/1.sh > ../../../public/result.txt'), 1);
  assert.equal(scriptRiskFor('bash scripts/setup.sh'), 1);
  assert.equal(scriptRiskFor('sh install.sh'), 1);
  assert.equal(scriptRiskFor('bash install.sh'), 1);
});

test('does not flag standard node-gyp rebuild and legitimate build scripts', () => {
  const benign = [
    'node-gyp rebuild',
    'npm run build',
    'npm run prepare',
    'tsc',
    'tsc -p .',
    'echo "ok"'
  ];
  for (const script of benign) {
    assert.equal(isSuspiciousScript(script), false, `expected benign: ${script}`);
    assert.equal(scriptRiskFor(script), 0, `expected no install-hook risk: ${script}`);
  }
});

test('does not flag non-install scripts such as test, lint and start', () => {
  const extracted = extractFeatures({
    metadata: {
      // normalized metadata carries only install hooks; non-install hooks are absent
      lifecycle_scripts: { preinstall: null, install: null, postinstall: null, prepare: null },
      dependency_version_ranges: [],
      dependency_count: 0,
      has_bin_entry: false,
      downloads: { weekly: 0, available: true },
      provenance: { present: false },
      provenance_history: []
    },
    request: { resolved_tag: 'pinned', nearest_popular_distance: 8, nearest_hallucination_distance: 8 },
    osvResult: { unavailable: false, knownCveCount: 0, maxSeverity: 0 }
  });
  assert.equal(extracted.featureVector.lifecycle_script_risk, 0);

  // detector may classify arbitrary strings, but non-install script fields are not evaluated as install risk
  assert.equal(isSuspiciousScript('node new.js'), true); // would be risky if in install hook
  // simulate that only test/lint/start exist (not in install hook set)
  const risk = scriptRiskFor(null);
  assert.equal(risk, 0);
});

test('distinguishes install-hook execution from ordinary build operations', () => {
  assert.equal(scriptRiskFor('node-gyp rebuild'), 0);
  assert.equal(scriptRiskFor('prebuild-install || node-gyp rebuild'), 0);
  assert.equal(scriptRiskFor('node new.js'), 1);
});
