#!/usr/bin/env node
// Builds the frozen "PACT External npm Test v1" case list. Metadata only: no tarballs, nothing installed.
// Malicious: DataDog npm manifest (pinned commit), excluding every NPMAnalysis package name.
// Benign: npm search results (popular + ordinary strata) plus a hand-listed stratum of legitimate
// packages with install scripts, excluding NPMAnalysis names, DataDog names and OSV-malicious hits.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const DIR = path.join(ROOT, 'analysis/2026-11-21-external-test');
// The test set is frozen: never overwrite it unless explicitly asked.
if (fs.existsSync(path.join(DIR, 'data/FREEZE.json')) && !process.argv.includes('--rebuild')) {
  console.error('external test set is frozen (data/FREEZE.json exists); pass --rebuild to regenerate it');
  process.exit(0);
}
const SEED = 20261121;
const DATADOG_COMMIT = '72c723be547033c558244520524b117c8d71663b';
const N_MALICIOUS_INTENT = 800;
const N_COMPROMISED = 200;
const N_POPULAR = 300;
const N_ORDINARY = 600;

// Deterministic PRNG (mulberry32) and shuffle.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function shuffle(items, random) {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function getJson(url, init) {
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      const res = await fetch(url, init);
      if (res.ok) return await res.json();
      if (res.status !== 429 && res.status < 500) throw new Error(`http_${res.status} ${url}`);
    } catch (error) {
      if (attempt === 5) throw error;
    }
    await sleep(1000 * 2 ** (attempt - 1));
  }
  throw new Error(`failed ${url}`);
}

// ---- exclusion lists
const npmanalysisCsv = fs.readFileSync(path.join(ROOT, 'analysis/2026-11-04-npmanalysis-accuracy/output/npmanalysis_cases.rebuilt.csv'), 'utf8').trim().split(/\r?\n/);
const naHeader = npmanalysisCsv.shift().split(',');
const nameCol = naHeader.indexOf('package_name');
const npmanalysisNames = new Set(npmanalysisCsv.map((l) => l.split(',')[nameCol].toLowerCase()));
const manifest = JSON.parse(fs.readFileSync(path.join(DIR, 'data/datadog_npm_manifest.json'), 'utf8'));
const datadogNames = new Set(Object.keys(manifest).map((n) => n.toLowerCase()));
const validName = (n) => /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9._~-][a-z0-9._~-]*$/.test(n);

// ---- malicious cohort
const random = rng(SEED);
const ddEntries = Object.entries(manifest).filter(([name]) => validName(name) && !npmanalysisNames.has(name.toLowerCase()));
const intent = shuffle(ddEntries.filter(([, v]) => v === null), random).slice(0, N_MALICIOUS_INTENT);
const compromised = shuffle(ddEntries.filter(([, v]) => Array.isArray(v) && v.length), random).slice(0, N_COMPROMISED);
const malicious = [
  // Malicious-intent packages: every version is malicious; evaluated unpinned (registry latest at run time).
  ...intent.map(([name]) => ({ package_name: name, package_version: '', label: 'malicious', stratum: 'datadog_malicious_intent' })),
  // Compromised libraries: one listed compromised version, chosen deterministically.
  ...compromised.map(([name, versions]) => ({ package_name: name, package_version: versions[Math.floor(random() * versions.length)], label: 'malicious', stratum: 'datadog_compromised_version' }))
];

// ---- benign cohort
const SEARCH_TERMS = ['react', 'cli', 'parser', 'http', 'logger', 'test', 'webpack', 'eslint-plugin', 'vue', 'date', 'color', 'string', 'array', 'config', 'stream', 'markdown', 'database', 'auth', 'image', 'cache', 'crypto', 'json', 'utility', 'server', 'css', 'svg', 'graphql', 'typescript', 'redux', 'express-middleware', 'babel-plugin', 'aws', 'file', 'queue', 'validation', 'template', 'socket', 'chart', 'i18n', 'math'];
const INSTALL_SCRIPT_PACKAGES = ['esbuild', 'prisma', '@prisma/client', 'sharp', 'husky', 'core-js', 'bcrypt', 'sqlite3', 'better-sqlite3', 'puppeteer', 'electron', 'canvas', 'cypress', 'protobufjs', 'es5-ext', '@swc/core', 'deasync', 're2', 'leveldown', 'bufferutil', 'utf-8-validate', 'msgpackr-extract', 'cpu-features', 'ssh2', 'playwright', '@parcel/watcher', 'lmdb', 'dtrace-provider', 'kerberos', 'zeromq', 'node-pty', '@sentry/cli', 'ngrok', 'chromedriver', 'geckodriver', 'elm', 'pngquant-bin', 'gifsicle', 'mozjpeg', 'optipng-bin', '@tensorflow/tfjs-node', 'aws-crt', 'oracledb', 'keytar', 'robotjs', 'node-hid', 'serialport', 'usb', 'node-sass', 'nodemon', 'spawn-sync', 'nice-napi', 'unix-dgram', 'couchbase', 'argon2', 'grpc', 'isolated-vm', 'microtime', 'farmhash', 'ffi-napi'];

async function search(text, from, weights) {
  const q = new URLSearchParams({ text, size: '250', from: String(from), ...weights });
  const body = await getJson(`https://registry.npmjs.org/-/v1/search?${q}`);
  return (body.objects ?? []).map((o) => ({ name: o.package.name, version: o.package.version, downloads_weekly: o.downloads?.weekly ?? null }));
}

const candidates = new Map();
for (const term of SEARCH_TERMS) {
  for (const [stratum, weights, from] of [
    ['npm_popular', { popularity: '1.0', quality: '0.0', maintenance: '0.0' }, 0],
    ['npm_ordinary', { popularity: '0.0', quality: '0.5', maintenance: '0.5' }, 500]
  ]) {
    const results = await search(term, from, weights);
    for (const r of results) {
      if (!candidates.has(r.name)) candidates.set(r.name, { ...r, stratum });
    }
    await sleep(300);
  }
}
const eligible = (name) => validName(name) && !npmanalysisNames.has(name.toLowerCase()) && !datadogNames.has(name.toLowerCase());

const installScript = [];
for (const name of INSTALL_SCRIPT_PACKAGES) {
  if (!eligible(name)) { console.log(`skip install-script ${name}: excluded`); continue; }
  try {
    const doc = await getJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    const version = doc['dist-tags']?.latest;
    const scripts = doc.versions?.[version]?.scripts ?? {};
    const hasHook = ['preinstall', 'install', 'postinstall', 'prepare'].some((h) => scripts[h]);
    if (version && hasHook) installScript.push({ name, version, stratum: 'legit_install_script' });
    else console.log(`skip install-script ${name}: no install hook in ${version}`);
  } catch (error) {
    console.log(`skip install-script ${name}: ${error.message}`);
  }
  await sleep(150);
}
const installNames = new Set(installScript.map((p) => p.name));
const pool = [...candidates.values()].filter((c) => eligible(c.name) && !installNames.has(c.name));
const popular = shuffle(pool.filter((c) => c.stratum === 'npm_popular'), random).slice(0, N_POPULAR);
const ordinary = shuffle(pool.filter((c) => c.stratum === 'npm_ordinary'), random).slice(0, N_ORDINARY);
let benign = [...popular, ...ordinary, ...installScript];

// Exclude any benign candidate with an OSV malicious advisory at snapshot time.
const osvMalicious = new Set();
for (let i = 0; i < benign.length; i += 500) {
  const chunk = benign.slice(i, i + 500);
  const body = await getJson('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })) })
  });
  body.results.forEach((result, j) => {
    if ((result.vulns ?? []).some((v) => String(v.id).startsWith('MAL-'))) osvMalicious.add(chunk[j].name);
  });
}
benign = benign.filter((p) => !osvMalicious.has(p.name));

const benignRows = benign.map((p) => ({ package_name: p.name, package_version: p.version, label: 'benign', stratum: p.stratum }));
const rows = [...malicious, ...benignRows];

// ---- write frozen artifacts
const csv = ['package_name,package_version,label,stratum', ...rows.map((r) => [r.package_name, r.package_version, r.label, r.stratum].join(','))].join('\n') + '\n';
fs.writeFileSync(path.join(DIR, 'data/external_test_v1.csv'), csv);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const counts = rows.reduce((acc, r) => { acc[r.stratum] = (acc[r.stratum] ?? 0) + 1; return acc; }, {});
const freeze = {
  name: 'PACT External npm Test v1',
  frozen_at: new Date().toISOString(),
  seed: SEED,
  case_list_sha256: sha(csv),
  datadog: { repo: 'DataDog/malicious-software-packages-dataset', commit: DATADOG_COMMIT, manifest_sha256: sha(fs.readFileSync(path.join(DIR, 'data/datadog_npm_manifest.json'))) },
  version_rules: {
    datadog_malicious_intent: 'unpinned; evaluated against the registry latest at run time (all versions are malicious)',
    datadog_compromised_version: 'one listed compromised version, chosen with the seeded PRNG',
    benign: 'exact latest version at snapshot time'
  },
  exclusions: {
    all: 'every NPMAnalysis package name (both labels)',
    benign: 'DataDog manifest names; packages with an OSV MAL- advisory for the pinned version at snapshot time',
    benign_osv_malicious_removed: [...osvMalicious]
  },
  counts: { total: rows.length, malicious: malicious.length, benign: benignRows.length, by_stratum: counts },
  rule: 'Do not evaluate, inspect results, or tune against this set until all development steps are final.'
};
fs.writeFileSync(path.join(DIR, 'data/FREEZE.json'), `${JSON.stringify(freeze, null, 2)}\n`);
console.log(JSON.stringify(freeze.counts, null, 2));
