import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchDownloads } from '../src/connectors/npm.js';
import { compareVersionMaintainers, normalizeMetadata } from '../src/metadata-normalizer.js';
import { extractFeatures } from '../src/feature-extractor.js';

function scriptedFetcher(responses) {
  let calls = 0;
  const fetcher = async () => {
    const next = responses[Math.min(calls, responses.length - 1)];
    calls += 1;
    if (next instanceof Error) throw next;
    return next;
  };
  return { fetcher, calls: () => calls };
}

const fast = { backoffMs: 0 };

test('downloads: returns the weekly count on success', async () => {
  const { fetcher } = scriptedFetcher([{ ok: true, status: 200, body: { downloads: 42 } }]);
  const result = await fetchDownloads('pkg', 1000, { ...fast, fetcher });
  assert.deepEqual(result, { weekly: 42, available: true, status: 'ok', attempts: 1 });
});

test('downloads: retries rate limits and timeouts before succeeding', async () => {
  const { fetcher, calls } = scriptedFetcher([
    { ok: false, status: 429 },
    new Error('request_timeout'),
    { ok: true, status: 200, body: { downloads: 7 } }
  ]);
  const result = await fetchDownloads('pkg', 1000, { ...fast, fetcher });
  assert.equal(result.status, 'ok');
  assert.equal(result.weekly, 7);
  assert.equal(calls(), 3);
});

test('downloads: a persistent failure is unknown, not zero', async () => {
  const { fetcher, calls } = scriptedFetcher([{ ok: false, status: 503 }]);
  const result = await fetchDownloads('pkg', 1000, { ...fast, fetcher });
  assert.equal(result.status, 'failed');
  assert.equal(result.available, false);
  assert.equal(result.weekly, null);
  assert.equal(result.error, 'http_503');
  assert.equal(calls(), 5);
});

test('downloads: honours Retry-After on rate limits', async () => {
  const { fetcher, calls } = scriptedFetcher([
    { ok: false, status: 429, retryAfterMs: 1 },
    { ok: true, status: 200, body: { downloads: 3 } }
  ]);
  const result = await fetchDownloads('pkg', 1000, { backoffMs: 60000, fetcher });
  assert.equal(result.status, 'ok');
  assert.equal(calls(), 2);
});

test('downloads: does not retry non-retryable errors', async () => {
  const { fetcher, calls } = scriptedFetcher([{ ok: false, status: 400 }]);
  const result = await fetchDownloads('pkg', 1000, { ...fast, fetcher });
  assert.equal(result.status, 'failed');
  assert.equal(calls(), 1);
});

test('downloads: 404 for an existing package means no recorded downloads', async () => {
  const { fetcher, calls } = scriptedFetcher([{ ok: false, status: 404 }]);
  const result = await fetchDownloads('pkg', 1000, { ...fast, fetcher });
  assert.deepEqual(result, { weekly: 0, available: true, status: 'no_data', attempts: 1 });
  assert.equal(calls(), 1);
});

test('downloads: failed lookup leaves popularity unavailable, not low-risk', () => {
  const metadata = normalizeMetadata(
    { name: 'pkg', versions: { '1.0.0': {} }, time: { '1.0.0': '2020-01-01T00:00:00Z' } },
    '1.0.0',
    'pinned',
    { downloads: { weekly: null, available: false, status: 'failed' } }
  );
  assert.equal(metadata.downloads.status, 'failed');
  const { availability } = extractFeatures({ metadata, request: {}, osvResult: { unavailable: false } });
  assert.equal(availability.popularity_risk, false);
});

test('maintainers: detects a maintainer added since the previous version (event-stream pattern)', () => {
  const result = compareVersionMaintainers(
    { maintainers: [{ name: 'dominictarr' }, { name: 'right9ctrl' }] },
    { maintainers: [{ name: 'dominictarr' }] }
  );
  assert.deepEqual(result, { available: true, changed: true, added: ['right9ctrl'] });
});

test('maintainers: unchanged, reordered, or removed-only lists are not a change', () => {
  assert.equal(compareVersionMaintainers({ maintainers: [{ name: 'b' }, { name: 'a' }] }, { maintainers: [{ name: 'a' }, { name: 'b' }] }).changed, false);
  assert.equal(compareVersionMaintainers({ maintainers: [{ name: 'a' }] }, { maintainers: [{ name: 'a' }, { name: 'b' }] }).changed, false);
});

test('maintainers: unavailable for a first version or missing lists', () => {
  assert.equal(compareVersionMaintainers({ maintainers: [{ name: 'a' }] }, null).available, false);
  assert.equal(compareVersionMaintainers({}, { maintainers: [{ name: 'a' }] }).available, false);
});

test('maintainers: feature fires end-to-end through normalizer and extractor', () => {
  const raw = {
    name: 'pkg',
    versions: {
      '1.0.0': { maintainers: [{ name: 'owner' }] },
      '1.0.1': { maintainers: [{ name: 'owner' }, { name: 'newcomer' }] }
    },
    time: { '1.0.0': '2020-01-01T00:00:00Z', '1.0.1': '2020-02-01T00:00:00Z' }
  };
  const metadata = normalizeMetadata(raw, '1.0.1', 'pinned', {});
  const { featureVector, availability } = extractFeatures({ metadata, request: {}, osvResult: { unavailable: false } });
  assert.equal(availability.maintainer_changed_risk, true);
  assert.equal(featureVector.maintainer_changed_risk, 1);
});
