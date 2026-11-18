import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parsePackageSpec, normalizeText } from './utils.js';

export function allowlistPath() {
  return process.env.PACT_ALLOWLIST_FILE
    ?? path.join(process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), '.config'), 'pact', 'allowlist.json');
}

function normalizePackageName(value) {
  const parsed = parsePackageSpec(value);
  if (!parsed.valid || !parsed.name || parsed.name.includes('://') || parsed.name.startsWith('.') || parsed.name.startsWith('/')) {
    throw new Error(`invalid_allowlist_package:${value}`);
  }
  return normalizeText(parsed.name);
}

export function readAllowlist(filePath = allowlistPath()) {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  try {
    const document = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return [...new Set((document.packages ?? []).map(normalizePackageName))].sort();
  } catch (error) {
    throw new Error(`invalid_allowlist_file:${filePath}:${error.message}`);
  }
}

function writeAllowlist(packages, filePath = allowlistPath()) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify({ packages: [...new Set(packages)].sort() }, null, 2)}\n`, 'utf8');
}

export function addAllowlistedPackage(packageSpec, filePath = allowlistPath()) {
  const packageName = normalizePackageName(packageSpec);
  const packages = readAllowlist(filePath);
  if (!packages.includes(packageName)) {
    packages.push(packageName);
    writeAllowlist(packages, filePath);
  }
  return { packageName, packages: readAllowlist(filePath), filePath };
}

export function removeAllowlistedPackage(packageSpec, filePath = allowlistPath()) {
  const packageName = normalizePackageName(packageSpec);
  const packages = readAllowlist(filePath).filter((entry) => entry !== packageName);
  writeAllowlist(packages, filePath);
  return { packageName, packages, filePath };
}

export function isAllowlisted(packageSpec, filePath = allowlistPath()) {
  const parsed = parsePackageSpec(packageSpec);
  if (!parsed.valid) {
    return false;
  }
  return readAllowlist(filePath).includes(normalizeText(parsed.name));
}

export function createBypassDecision(packageSpec, filePath = allowlistPath()) {
  const parsed = parsePackageSpec(packageSpec);
  const packageName = parsed.valid ? normalizeText(parsed.name) : normalizeText(packageSpec);
  const timestamp = new Date().toISOString();
  const decision = {
    timestamp,
    requested_package: {
      name: packageName,
      version: parsed.valid ? parsed.version : null,
      ecosystem: 'npm'
    },
    existence_check: { status: 'bypassed' },
    osv_result: { status: 'bypassed' },
    feature_vector: null,
    trust_engine_version: 'not_run',
    risk_score: null,
    decision: 'BYPASS',
    confidence: null,
    evidence_completeness: 0,
    unavailable_features: ['all_security_features'],
    reason: 'bypassed: explicit_user_allowlist',
    contributing_signals: [],
    bypass: {
      type: 'explicit_user_allowlist',
      allowlist_file: filePath
    }
  };

  return { decision, logEntry: decision };
}
