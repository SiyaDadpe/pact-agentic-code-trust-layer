import { fileTimeIso } from './utils.js';

function asArray(value) {
  if (!value) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function selectVersionInfo(rawMetadata, resolvedVersion) {
  return rawMetadata?.versions?.[resolvedVersion] ?? null;
}

function versionEntries(rawMetadata) {
  return Object.entries(rawMetadata?.versions ?? {})
    .map(([version, metadata]) => ({
      version,
      metadata,
      timestamp: fileTimeIso(rawMetadata?.time?.[version])
    }))
    .filter((entry) => entry.timestamp)
    .sort((left, right) => left.timestamp.localeCompare(right.timestamp));
}

function maintainerNames(versionMetadata) {
  return asArray(versionMetadata?.maintainers)
    .map((maintainer) => (typeof maintainer === 'string' ? maintainer : maintainer?.name ?? maintainer?.email ?? null))
    .filter(Boolean)
    .map((name) => String(name).trim().toLowerCase());
}

// A maintainer change means someone is listed on the selected version who was not listed on the
// previous version (the event-stream takeover pattern). Removals alone are not treated as a change.
// Unavailable when there is no previous version or either version lacks a maintainer list.
export function compareVersionMaintainers(selectedVersion, previousVersion) {
  const current = maintainerNames(selectedVersion);
  const previous = maintainerNames(previousVersion);
  if (!current.length || !previous.length) {
    return { available: false, changed: false, added: [] };
  }
  const previousSet = new Set(previous);
  const added = [...new Set(current.filter((name) => !previousSet.has(name)))];
  return { available: true, changed: added.length > 0, added };
}

export function normalizeMetadata(rawMetadata, resolvedVersion, resolvedTag, request) {
  const selectedVersion = selectVersionInfo(rawMetadata, resolvedVersion);
  const history = versionEntries(rawMetadata);
  const selectedIndex = history.findIndex((entry) => entry.version === resolvedVersion);
  const previousVersion = selectedIndex > 0 ? history[selectedIndex - 1] : null;
  const timeMap = rawMetadata?.time ?? {};
  const versionPublishTimestamps = Object.entries(timeMap)
    .filter(([key]) => key !== 'created' && key !== 'modified' && key !== 'unpublished')
    .map(([, value]) => fileTimeIso(value))
    .filter(Boolean)
    .sort();

  const publishTimestamp = fileTimeIso(timeMap?.[resolvedVersion] ?? timeMap?.modified ?? null);
  const firstPublishTimestamp = versionPublishTimestamps[0] ?? publishTimestamp;
  const maintainers = asArray(rawMetadata?.maintainers).map((maintainer) => maintainer?.name ?? maintainer?.email ?? String(maintainer)).filter(Boolean);
  const dependencies = Object.keys(selectedVersion?.dependencies ?? {});
  const dependencyVersionRanges = Object.entries(selectedVersion?.dependencies ?? {}).map(([name, range]) => ({ name, range }));
  const scripts = selectedVersion?.scripts ?? {};
  const dist = selectedVersion?.dist ?? {};
  const attestations = selectedVersion?.dist?.attestations ?? null;
  const provenance = Boolean(attestations ?? selectedVersion?.provenance ?? rawMetadata?.provenance ?? false);
  const provenanceSource = attestations?.url ?? attestations?.provenance ?? selectedVersion?.provenance?.source ?? rawMetadata?.provenance?.source ?? null;
  const provenanceHistory = Object.entries(rawMetadata?.versions ?? {}).map(([version, versionMeta]) => ({
    version,
    present: Boolean(versionMeta?.dist?.attestations ?? versionMeta?.provenance ?? false)
  }));
  const currentPublisher = selectedVersion?._npmUser?.name ?? selectedVersion?._npmUser?.email ?? null;
  const previousPublisher = previousVersion?.metadata?._npmUser?.name ?? previousVersion?.metadata?._npmUser?.email ?? null;
  const maintainerChange = compareVersionMaintainers(selectedVersion, previousVersion?.metadata);
  const requestDownloads = request?.downloads ?? null;
  const weeklyDownloads = requestDownloads?.weekly ?? rawMetadata?.downloads?.weekly ?? null;

  return {
    name: rawMetadata?.name ?? request?.full_name ?? request?.name ?? '',
    version: resolvedVersion ?? request?.version ?? null,
    publish_timestamp: publishTimestamp,
    first_publish_timestamp: firstPublishTimestamp,
    version_publish_timestamps: versionPublishTimestamps,
    dist_tags: rawMetadata?.['dist-tags'] ?? {},
    resolved_tag: resolvedTag,
    maintainers,
    maintainer_count: maintainers.length,
    author: selectedVersion?.author?.name ?? rawMetadata?.author?.name ?? rawMetadata?.author ?? null,
    license: selectedVersion?.license ?? rawMetadata?.license ?? null,
    homepage: selectedVersion?.homepage ?? rawMetadata?.homepage ?? null,
    repository_url: selectedVersion?.repository?.url ?? rawMetadata?.repository?.url ?? null,
    bugs_url: selectedVersion?.bugs?.url ?? rawMetadata?.bugs?.url ?? null,
    description: selectedVersion?.description ?? rawMetadata?.description ?? '',
    keywords: asArray(selectedVersion?.keywords ?? rawMetadata?.keywords),
    dependencies,
    dependency_count: dependencies.length,
    dependency_version_ranges: dependencyVersionRanges,
    lifecycle_scripts: {
      preinstall: scripts.preinstall ?? null,
      install: scripts.install ?? null,
      postinstall: scripts.postinstall ?? null,
      prepare: scripts.prepare ?? null
    },
    has_bin_entry: Boolean(selectedVersion?.bin ?? rawMetadata?.bin),
    integrity: {
      sha512: dist.integrity?.includes('sha512-') ? dist.integrity : null,
      sha1: dist.shasum ?? null
    },
    provenance: {
      present: provenance,
      source: provenanceSource,
      available: Boolean(attestations ?? selectedVersion?.provenance ?? rawMetadata?.provenance ?? provenanceHistory.some((entry) => entry.present))
    },
    provenance_history: provenanceHistory,
    provenance_available: Boolean(attestations ?? selectedVersion?.provenance ?? rawMetadata?.provenance ?? provenanceHistory.some((entry) => entry.present)),
    publisher_changed_available: Boolean(currentPublisher && previousPublisher),
    maintainer_changed_available: maintainerChange.available,
    publisher_changed: Boolean(currentPublisher && previousPublisher && currentPublisher !== previousPublisher),
    maintainer_changed: maintainerChange.changed,
    maintainers_added: maintainerChange.added,
    downloads: {
      weekly: weeklyDownloads,
      available: requestDownloads?.available ?? typeof weeklyDownloads === 'number',
      status: requestDownloads?.status ?? (typeof weeklyDownloads === 'number' ? 'ok' : 'failed'),
      error: requestDownloads?.error ?? null,
      monthly: rawMetadata?.downloads?.monthly ?? null,
      trend: rawMetadata?.downloads?.trend ?? null
    }
  };
}