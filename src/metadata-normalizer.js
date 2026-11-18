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
  const currentMaintainers = maintainers.join('|');
  const previousMaintainers = asArray(rawMetadata?.maintainers)
    .map((maintainer) => maintainer?.name ?? maintainer?.email ?? String(maintainer))
    .filter(Boolean)
    .join('|');

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
    maintainer_changed_available: false,
    publisher_changed: Boolean(currentPublisher && previousPublisher && currentPublisher !== previousPublisher),
    maintainer_changed: Boolean(currentMaintainers && previousMaintainers && currentMaintainers !== previousMaintainers),
    downloads: {
      weekly: request?.downloads?.weekly ?? rawMetadata?.downloads?.weekly ?? null,
      monthly: rawMetadata?.downloads?.monthly ?? null,
      trend: rawMetadata?.downloads?.trend ?? null
    }
  };
}