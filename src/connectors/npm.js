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
      return { ok: false, status: response.status };
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

  try {
    const downloads = await fetchJson(`${NPM_DOWNLOADS_BASE}/${encodeURIComponent(name)}`, timeoutMs);
    value.downloads = downloads.ok
      ? { weekly: downloads.body?.downloads ?? null, available: true }
      : { weekly: null, available: false };
  } catch {
    value.downloads = { weekly: null, available: false };
  }

  cache.set(key, { expiresAt: now + REGISTRY_TTL_MS, value });
  return value;
}