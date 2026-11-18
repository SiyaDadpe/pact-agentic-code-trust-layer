import { OSV_QUERY_URL, REGISTRY_TTL_MS } from '../constants.js';

const cache = new Map();

function cacheKey(name, version, ecosystem) {
  return `${ecosystem}::${name}::${version ?? ''}`;
}

function severityRank(severity) {
  const numericScore = Number(severity);
  if (Number.isFinite(numericScore)) {
    return Math.max(0, Math.min(numericScore / 10, 1));
  }

  const text = String(severity ?? '').toUpperCase();
  if (text.includes('CRITICAL')) {
    return 1;
  }
  if (text.includes('HIGH')) {
    return 0.85;
  }
  if (text.includes('MEDIUM')) {
    return 0.55;
  }
  if (text.includes('LOW')) {
    return 0.25;
  }
  return 0;
}

function looksMalicious(vulnerability) {
  const id = String(vulnerability?.id ?? '').toUpperCase();
  return id.startsWith('MAL-');
}

async function fetchJson(url, body, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('request_timeout')), timeoutMs);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!response.ok) {
      return { ok: false, status: response.status };
    }
    return { ok: true, status: response.status, body: await response.json() };
  } finally {
    clearTimeout(timeout);
  }
}

export async function checkOsv(name, version, ecosystem = 'npm', options = {}) {
  const { timeoutMs = 5000 } = options;
  const key = cacheKey(name, version, ecosystem);
  const cached = cache.get(key);
  const now = Date.now();

  if (cached && cached.expiresAt > now) {
    return { ...cached.value, cacheHit: true };
  }

  if (!version) {
    const value = {
      cacheHit: false,
      malicious: false,
      vulnerabilities: [],
      advisoryCount: 0,
      knownCveCount: 0,
      maxSeverity: 0,
      unavailable: true
    };
    cache.set(key, { expiresAt: now + REGISTRY_TTL_MS, value });
    return value;
  }

  const payload = {
    package: { name, ecosystem },
    version
  };

  const fetched = await fetchJson(OSV_QUERY_URL, payload, timeoutMs);
  if (!fetched.ok) {
    throw new Error(`osv_unavailable:${fetched.status}`);
  }

  const vulnerabilities = Array.isArray(fetched.body?.vulns) ? fetched.body.vulns : [];
  const maxSeverity = vulnerabilities.reduce((max, vulnerability) => {
    const severity = Array.isArray(vulnerability.severity) && vulnerability.severity.length > 0
      ? Math.max(...vulnerability.severity.map((entry) => severityRank(entry.score ?? entry.type ?? entry.severity)))
      : 0;
    return Math.max(max, severity);
  }, 0);

  const malicious = vulnerabilities.some(looksMalicious);
  const value = {
    cacheHit: false,
    malicious,
    vulnerabilities,
    advisoryCount: vulnerabilities.length,
    knownCveCount: vulnerabilities.length,
    maxSeverity,
    unavailable: false
  };

  cache.set(key, { expiresAt: now + REGISTRY_TTL_MS, value });
  return value;
}