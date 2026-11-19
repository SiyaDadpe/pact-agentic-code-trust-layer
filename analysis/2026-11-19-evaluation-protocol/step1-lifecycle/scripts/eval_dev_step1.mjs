#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzePackageRequest } from '../../../../src/orchestrator.js';
import { scoreWithRuleEngine } from '../../../../src/trust-engine.js';
import { decidePackageRisk } from '../../../../src/decision-engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../../..');

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i === -1 ? def : process.argv[i + 1];
}
const csvPath = path.resolve(arg('--csv', path.join(ROOT, 'analysis/2026-11-19-evaluation-protocol/step1-lifecycle/data/dev_cases.csv')));
const outPath = path.resolve(arg('--out', path.join(ROOT, 'analysis/2026-11-19-evaluation-protocol/step1-lifecycle/output/dev_step1_detailed.jsonl')));
const frozenPath = path.resolve(arg('--frozen', path.join(ROOT, 'analysis/2026-11-19-evaluation-protocol/step1-lifecycle/output/dev_baseline_frozen.jsonl')));
const concurrency = Math.max(1, Number(arg('--concurrency', '12')));
const timeoutMs = Math.max(1000, Number(arg('--timeout-ms', '10000')));
const limit = Math.max(0, Number(arg('--limit', '0')));

function parseCsv(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
  const lines = text.split(/\r?\n/).filter((l) => l.length);
  const header = lines.shift().split(',');
  return lines.map((line) => {
    // simple csv (no quoted commas in our fields)
    const vals = line.split(',');
    const obj = {};
    header.forEach((k, i) => obj[k] = vals[i] ?? '');
    return obj;
  });
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const rows = [];
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { rows.push(JSON.parse(line)); } catch {}
  }
  return rows;
}

function isSuspiciousScriptOld(scriptValue) {
  const script = scriptValue == null ? '' : String(scriptValue).trim();
  if (!script) return false;
  return /(?:curl|wget|powershell|invoke-webrequest|bash\s+-c|sh\s+-c|chmod\s+\+x|nc\s|netcat|python\s+-c|node\s+(?:-e|[^\n]*(?:setup|install|preinstall|postinstall)\.js)|base64\s+-d|eval\s*\(|require\s*\(|iwr\b)/i.test(script);
}

function deriveScriptRiskOld(lifecycleScripts) {
  const values = Object.values(lifecycleScripts ?? {}).filter(Boolean);
  if (!values.length) {
    return { value: 0, available: lifecycleScripts !== undefined };
  }
  const suspicious = values.some(isSuspiciousScriptOld);
  return { value: suspicious ? 1 : 0, available: true };
}

function pickDecisionFields(d) {
  if (!d) return null;
  return {
    decision: d.decision ?? d.action ?? null,
    risk_score: d.risk_score ?? d.riskScore ?? null,
    confidence: d.confidence ?? null,
    reason: d.reason ?? null,
    policy_rule: d.policy_rule ?? null,
    contributing_signals: d.contributing_signals ?? null,
    evidence_completeness: d.evidence_completeness ?? null
  };
}

async function processCase(row) {
  const spec = `${row.package_name}@${row.package_version}`;
  let result, error = null;
  try {
    result = await analyzePackageRequest({ spec, ecosystem: 'npm' }, { timeoutMs });
  } catch (e) {
    error = String(e?.message ?? e);
  }

  const frozen = frozenBySource.get(row.source_path) || null;
  const rec = {
    package_name: row.package_name,
    package_version: row.package_version,
    label: row.label,
    source_path: row.source_path,
    spec,
    frozen: frozen ? {
      decision: frozen.decision,
      risk_score: frozen.risk_score,
      confidence: frozen.confidence,
      existence_status: frozen.existence_status,
      osv_malicious: frozen.osv_malicious,
      osv_unavailable: frozen.osv_unavailable,
      reason: frozen.reason
    } : null,
    error
  };

  if (!result) {
    rec.step1 = null;
    rec.sim_old = null;
    return rec;
  }

  const d = result.decision || {};
  const existence = result.existenceCheck?.status ?? d.existence_check?.status ?? result.decision?.existence_check?.status ?? null;
  const lifecycleScripts = result.normalizedMetadata?.lifecycle_scripts ?? null;
  const fv = result.featureVector ?? d.feature_vector ?? null;
  const avail = result.featureAvailability ?? null;

  rec.step1 = {
    ...pickDecisionFields(d),
    existence_status: existence,
    osv_malicious: result.osvResult?.malicious ?? null,
    osv_unavailable: result.osvResult?.unavailable ?? null,
    feature_vector: fv,
    feature_availability: avail,
    lifecycle_scripts: lifecycleScripts,
    trust_score: result.trustScore ? { value: result.trustScore.value, breakdown: result.trustScore.breakdown, completeness: result.trustScore.completeness } : null
  };

  // simulate old detector on same snapshot
  let simOld = { applicable: false, reason: 'no_scoring' };
  const reachedScoring = fv && existence === 'exists' && !(result.osvResult?.malicious) && !(result.osvResult?.unavailable) && result.decision?.decision !== 'UNKNOWN' || (fv && result.trustScore);
  // More precise: short-circuits are missing_package, missing_version, registry_unavailable, osv_unavailable, known_malicious
  const shortCircuit = ['missing_package','missing_version','registry_unavailable','invalid_request'].includes(existence) || result.osvResult?.malicious || result.osvResult?.unavailable;
  if (shortCircuit) {
    simOld = { applicable: false, reason: 'short_circuit', short_circuit: existence || (result.osvResult?.malicious ? 'known_malicious' : result.osvResult?.unavailable ? 'osv_unavailable' : 'unknown') };
  } else if (fv && result.trustScore) {
    const oldScript = deriveScriptRiskOld(lifecycleScripts || {});
    const oldFv = { ...fv, lifecycle_script_risk: oldScript.value };
    const scoredOld = scoreWithRuleEngine(oldFv, avail || {});
    const decidedOld = decidePackageRisk({
      riskScore: scoredOld.value,
      breakdown: scoredOld.breakdown,
      completeness: result.trustScore.completeness ?? extractedCompleteness(avail),
      availability: avail || {},
      featureVector: oldFv,
      existenceCheck: { status: existence, version_exists: result.registryResult?.versionExists },
      osvResult: result.osvResult || { malicious: false }
    });
    simOld = {
      applicable: true,
      lifecycle_script_risk_old: oldScript.value,
      lifecycle_script_risk_new: fv.lifecycle_script_risk,
      feature_vector_old: oldFv,
      trust_score_old: { value: scoredOld.value, breakdown: scoredOld.breakdown },
      decision: {
        decision: decidedOld.action,
        risk_score: decidedOld.risk_score,
        confidence: decidedOld.confidence,
        reason: decidedOld.reason,
        policy_rule: decidedOld.policy_rule ?? null,
        contributing_signals: decidedOld.contributing_signals
      }
    };
  } else if (fv) {
    // exists but maybe unknown path; try recompute if no short circuit
    const oldScript = deriveScriptRiskOld(lifecycleScripts || {});
    const oldFv = { ...fv, lifecycle_script_risk: oldScript.value };
    simOld = { applicable: false, reason: 'no_trust_score', lifecycle_script_risk_old: oldScript.value, lifecycle_script_risk_new: fv.lifecycle_script_risk, feature_vector_old: oldFv };
  } else {
    simOld = { applicable: false, reason: 'no_feature_vector' };
  }
  rec.sim_old = simOld;
  return rec;
}

function extractedCompleteness(avail) {
  if (!avail) return null;
  const vals = Object.values(avail);
  return vals.length ? vals.filter(Boolean).length / vals.length : null;
}

const cases = limit ? parseCsv(csvPath).slice(0, limit) : parseCsv(csvPath);
const frozenRows = readJsonl(frozenPath);
const frozenBySource = new Map(frozenRows.map(r => [r.source_path, r]));
const existing = readJsonl(outPath);
const done = new Set(existing.map(r => r.source_path));
const pending = cases.filter(c => !done.has(c.source_path));

fs.mkdirSync(path.dirname(outPath), { recursive: true });
let completed = existing.length;
let idx = 0;

async function worker() {
  while (true) {
    const i = idx++;
    if (i >= pending.length) return;
    const rec = await processCase(pending[i]);
    fs.appendFileSync(outPath, JSON.stringify(rec) + '\n');
    completed++;
    if (completed % 50 === 0 || completed === cases.length) {
      console.error(`progress ${completed}/${cases.length}`);
    }
  }
}

await Promise.all(Array.from({ length: Math.min(concurrency, pending.length || 1) }, () => worker()));
console.log(JSON.stringify({ total: cases.length, written: completed, out: outPath }));
