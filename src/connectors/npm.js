import { NPM_DOWNLOADS_BASE, PACKAGE_REGISTRY_BASE, REGISTRY_TTL_MS } from '../constants.js';
import { isDistTag, isExactSemver } from '../utils.js';

const cache = new Map();

function cacheKey(name, version) {
  return `${name}::${version ?? ''}`;
}

async function fetchJson(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('request_timeout')), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      const retryAfterHeader = response.headers?.get?.('retry-after');
      const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : NaN;
      return { ok: false, status: response.status, retryAfterMs: Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0 ? retryAfterSeconds * 1000 : null };
    }
    return { ok: true, status: response.status, body: await response.json() };
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeVersionSelection(document, requestedVersion) {
  if (!requestedVersion || isDistTag(requestedVersion)) {
    const resolvedTag = requestedVersion ? requestedVersion : 'latest';
    const resolvedVersion = document['dist-tags']?.[resolvedTag] ?? document['dist-tags']?.latest ?? null;
    return {
      resolvedVersion,
      resolvedTag,
      requestedVersion: requestedVersion ?? null,
      versionExists: Boolean(resolvedVersion)
    };
  }

  if (isExactSemver(requestedVersion)) {
    return {
      resolvedVersion: requestedVersion,
      resolvedTag: 'pinned',
      requestedVersion,
      versionExists: Boolean(document.versions?.[requestedVersion])
    };
  }

  const resolvedVersion = document['dist-tags']?.latest ?? null;
  return {
    resolvedVersion,
    resolvedTag: 'latest',
    requestedVersion,
    versionExists: Boolean(resolvedVersion)
  };
}

export async function fetchNpmPackage(name, requestedVersion, options = {}) {
  const { timeoutMs = 5000 } = options;
  const key = cacheKey(name, requestedVersion);
  const cached = cache.get(key);
  const now = Date.now();

  if (cached && cached.expiresAt > now) {
    return { ...cached.value, cacheHit: true };
  }

  const packageUrl = `${PACKAGE_REGISTRY_BASE}/${encodeURIComponent(name)}`;
  const fetched = await fetchJson(packageUrl, timeoutMs);

  if (!fetched.ok) {
    if (fetched.status === 404) {
      const value = { exists: false, cacheHit: false, requestedVersion: requestedVersion ?? null };
      cache.set(key, { expiresAt: now + REGISTRY_TTL_MS, value });
      return value;
    }
    throw new Error(`npm_registry_unavailable:${fetched.status}`);
  }

  const document = fetched.body;
  const versionSelection = normalizeVersionSelection(document, requestedVersion);
  const value = {
    exists: true,
    cacheHit: false,
    requestedVersion: requestedVersion ?? null,
    versionExists: versionSelection.versionExists,
    resolvedVersion: versionSelection.resolvedVersion,
    resolvedTag: versionSelection.resolvedTag,
    rawMetadata: document,
    rawVersionMetadata: versionSelection.resolvedVersion ? document.versions?.[versionSelection.resolvedVersion] ?? null : null
  };

  value.downloads = await fetchDownloads(name, timeoutMs);

  cache.set(key, { expiresAt: now + REGISTRY_TTL_MS, value });
  return value;
}

const DOWNLOAD_ATTEMPTS = 5;
const DOWNLOAD_BACKOFF_MS = 1000;
const DOWNLOAD_MAX_WAIT_MS = 30000;

function isRetryableStatus(status) {
  return status === 429 || status >= 500;
}

// Weekly downloads for a package that is already known to exist.
// status: 'ok'      -> count returned by the API
//         'no_data' -> API has no download record (404); the package exists, so this means zero downloads
//         'failed'  -> lookup failed after retries; the value is unknown, not zero
export async function fetchDownloads(name, timeoutMs = 5000, { attempts = DOWNLOAD_ATTEMPTS, backoffMs = DOWNLOAD_BACKOFF_MS, fetcher = fetchJson } = {}) {
  const url = `${NPM_DOWNLOADS_BASE}/${encodeURIComponent(name)}`;
  let lastError = null;
  let retryAfterMs = null;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetcher(url, timeoutMs);
      if (response.ok && typeof response.body?.downloads === 'number') {
        return { weekly: response.body.downloads, available: true, status: 'ok', attempts: attempt };
      }
      if (response.status === 404) {
        return { weekly: 0, available: true, status: 'no_data', attempts: attempt };
      }
      lastError = `http_${response.status}`;
      retryAfterMs = response.retryAfterMs ?? null;
      if (response.ok || !isRetryableStatus(response.status)) {
        break;
      }
    } catch (error) {
      lastError = error?.message ?? 'request_failed';
      retryAfterMs = null;
    }

    if (attempt < attempts) {
      // Honour a positive Retry-After (npm sends 0 on its 429s, which is ignored); otherwise exponential backoff with jitter.
      const exponential = backoffMs * 2 ** (attempt - 1) * (1 + Math.random() * 0.5);
      const waitMs = Math.min(retryAfterMs ?? exponential, DOWNLOAD_MAX_WAIT_MS);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  }

  return { weekly: null, available: false, status: 'failed', error: lastError, attempts };
}