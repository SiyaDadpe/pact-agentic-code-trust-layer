import test from 'node:test';
import assert from 'node:assert/strict';
import { hasRandomScriptFilename } from '../src/utils.js';
import { extractFeatures } from '../src/feature-extractor.js';
import { scoreWithRuleEngine } from '../src/trust-engine.js';
import { decidePackageRisk } from '../src/decision-engine.js';
import { popularPackages } from '../src/corpus.js';

function decide({ script = null, nearestPopularDistance = 8, name = 'some-package', weekly = 50 }) {
  const metadata = {
    lifecycle_scripts: { preinstall: null, install: null, postinstall: script, prepare: null },
    dependency_version_ranges: [],
    dependency_count: 0,
    has_bin_entry: false,
    downloads: { weekly, available: true },
    provenance: { present: false },
    provenance_history: []
  };
  const request = { full_name: name, resolved_tag: 'pinned', nearest_popular_distance: nearestPopularDistance, nearest_hallucination_distance: 8 };
  const { featureVector, availability, completeness } = extractFeatures({ metadata, request, osvResult: { unavailable: false } });
  const scored = scoreWithRuleEngine(featureVector, availability);
  return decidePackageRisk({
    riskScore: scored.value, breakdown: scored.breakdown, completeness, availability, featureVector,
    weeklyDownloads: weekly, existenceCheck: { status: 'exists' }, osvResult: { malicious: false }
  });
}

test('random script filenames are detected; descriptive and versioned names are not', () => {
  for (const s of ['node c0nlywxa.cjs', 'node 31kbzord.cjs', 'node ./saeyrw7c.cjs', 'node e22406bu.js']) {
    assert.equal(hasRandomScriptFilename(s), true, s);
  }
  for (const s of ['node install.js', 'node scripts/postinstall.js', 'node es2015.js', 'node sha256.js', 'node webpack5.js', 'node-gyp rebuild', 'node build.js || nodejs build.js']) {
    assert.equal(hasRandomScriptFilename(s), false, s);
  }
});

test('install script running a random filename is blocked in a non-established package', () => {
  const result = decide({ script: 'node c0nlywxa.cjs', weekly: 60 });
  assert.equal(result.action, 'BLOCK');
  assert.equal(result.policy_rule, 'install_script_runs_random_filename');
});

test('established packages are not blocked by the random-filename rule, only warned', () => {
  const result = decide({ script: 'node v8flags.js', weekly: 2_000_000 });
  assert.equal(result.action, 'WARN');
  assert.equal(result.policy_rule, 'install_script_requires_review');
});

test('install script plus a one-edit typosquat name is blocked', () => {
  const result = decide({ script: 'node index.js', nearestPopularDistance: 1, name: 'expresss-utils' });
  assert.equal(result.action, 'BLOCK');
  assert.equal(result.policy_rule, 'typosquat_with_install_script');
});

test('one-edit typosquat without an install script is warned, not blocked', () => {
  const result = decide({ nearestPopularDistance: 1, name: 'styled-component' });
  assert.equal(result.action, 'WARN');
  assert.equal(result.policy_rule, 'possible_typosquat_requires_review');
});

test('short names are not treated as one-edit typosquats', () => {
  const result = decide({ nearestPopularDistance: 1, name: 'chak' });
  assert.equal(result.action, 'ALLOW');
});

test('an established package one edit from a popular name is allowed', () => {
  const result = decide({ nearestPopularDistance: 1, name: 'preact-render', weekly: 500_000 });
  assert.equal(result.action, 'ALLOW');
});

test('popular corpus covers the top npm packages', () => {
  assert.equal(popularPackages.length, 5000);
  for (const name of ['react', 'lodash', 'express', 'semver', 'debug', 'typescript']) {
    assert.ok(popularPackages.includes(name), name);
  }
});
