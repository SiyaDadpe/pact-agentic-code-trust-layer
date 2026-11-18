import { EXPECTED_FEATURES } from './constants.js';
import {
  clamp,
  daysBetween,
  isSuspiciousScript,
  looksLikeBroadRange,
  packageAgeRiskFromTimestamp,
  versionAgeRiskFromTimestamp
} from './utils.js';

function deriveScriptRisk(lifecycleScripts) {
  const values = Object.values(lifecycleScripts ?? {}).filter(Boolean);
  if (!values.length) {
    return { value: 0, available: lifecycleScripts !== undefined };
  }
  const suspicious = values.some(isSuspiciousScript);
  return { value: suspicious ? 1 : 0, available: true };
}

function deriveReleaseBurstiness(versionPublishTimestamps) {
  if (!Array.isArray(versionPublishTimestamps) || versionPublishTimestamps.length < 2) {
    return { value: 0, available: false };
  }

  const recentWindowDays = 30;
  const now = new Date().toISOString();
  const recent = versionPublishTimestamps.filter((timestamp) => {
    const ageDays = daysBetween(timestamp, now);
    return ageDays !== null && ageDays <= recentWindowDays;
  }).length;
  const ratio = recent / Math.max(versionPublishTimestamps.length, 1);
  return { value: clamp(ratio * 1.5), available: true };
}

function deriveDependencyRisk(metadata) {
  const ranges = metadata?.dependency_version_ranges ?? [];
  if (!ranges.length) {
    return { value: 0, available: metadata?.dependency_version_ranges !== undefined };
  }

  const broadRanges = ranges.filter((entry) => looksLikeBroadRange(entry.range)).length;
  const urlDeps = ranges.filter((entry) => /^(?:git\+|https?:|file:|workspace:|link:)/i.test(String(entry.range ?? ''))).length;
  const dependencyCount = metadata?.dependency_count ?? 0;
  const value = clamp((dependencyCount / 20) * 0.4 + (broadRanges / ranges.length) * 0.4 + (urlDeps / ranges.length) * 0.2);
  return { value, available: true };
}

function deriveSimilarityRisk(distance) {
  if (distance === null || distance === undefined) {
    return { value: 0, available: false };
  }
  if (distance === 0) {
    return { value: 0, available: true };
  }
  return { value: clamp(1 - distance / 4), available: true };
}

function deriveCorpusRisk(distance) {
  if (distance === null || distance === undefined) {
    return { value: 0, available: false };
  }
  if (distance === 0) {
    return { value: 1, available: true };
  }
  return { value: clamp(1 - distance / 8), available: true };
}

function derivePopularityRisk(downloads) {
  const weekly = downloads?.weekly;
  if (downloads?.available === false || typeof weekly !== 'number') {
    return { value: 0, available: false };
  }
  return { value: clamp(1 - Math.min(Math.log10(weekly + 1) / 6, 1)), available: true };
}

function deriveCveRisk(osvResult) {
  if (!osvResult || osvResult.unavailable) {
    return { value: 0, available: false };
  }
  const count = osvResult.knownCveCount ?? osvResult.advisoryCount ?? 0;
  const severity = osvResult.maxSeverity ?? 0;
  return { value: clamp((count / 8) + severity * 0.5), available: true };
}

function deriveBooleanRisk(condition, available = true) {
  return { value: condition ? 1 : 0, available };
}

export function extractFeatures({ metadata, request, osvResult }) {
  const packageAge = packageAgeRiskFromTimestamp(metadata?.first_publish_timestamp);
  const versionAge = versionAgeRiskFromTimestamp(metadata?.publish_timestamp);
  const releaseBurstiness = deriveReleaseBurstiness(metadata?.version_publish_timestamps);
  const unusualTag = deriveBooleanRisk(Boolean(request?.resolved_tag && request.resolved_tag !== 'pinned' && request.resolved_tag !== 'latest'));
  const scriptRisk = deriveScriptRisk(metadata?.lifecycle_scripts);
  const executableRisk = deriveBooleanRisk(Boolean(metadata?.has_bin_entry) && (packageAge.value > 0.7 || (metadata?.downloads?.weekly ?? 0) < 1000), Boolean(metadata?.has_bin_entry));
  const provenanceRegression = deriveBooleanRisk(
    metadata?.provenance_available && metadata?.provenance?.present === false && metadata?.provenance_history?.some((entry) => entry.present),
    Boolean(metadata?.provenance_available)
  );
  const publisherChanged = deriveBooleanRisk(Boolean(metadata?.publisher_changed), metadata?.publisher_changed_available ?? false);
  const maintainerChanged = deriveBooleanRisk(Boolean(metadata?.maintainer_changed), metadata?.maintainer_changed_available ?? false);
  const dependencyRisk = deriveDependencyRisk(metadata);
  const similarityRisk = deriveSimilarityRisk(request?.nearest_popular_distance);
  const corpusRisk = request?.nearest_popular_distance === 0 ? { value: 0, available: true } : deriveCorpusRisk(request?.nearest_hallucination_distance);
  const popularityRisk = derivePopularityRisk(metadata?.downloads);
  const cveRisk = deriveCveRisk(osvResult);

  const featureVector = {
    package_age_risk: packageAge.value,
    version_age_risk: versionAge.value,
    release_burstiness_risk: releaseBurstiness.value,
    unusual_tag_risk: unusualTag.value,
    lifecycle_script_risk: scriptRisk.value,
    executable_flag_risk: executableRisk.value,
    provenance_regression_risk: provenanceRegression.value,
    publisher_changed_risk: publisherChanged.value,
    maintainer_changed_risk: maintainerChanged.value,
    dependency_risk: dependencyRisk.value,
    name_similarity_risk: similarityRisk.value,
    hallucination_corpus_risk: corpusRisk.value,
    popularity_risk: popularityRisk.value,
    cve_risk: cveRisk.value
  };

  const availability = {
    package_age_risk: packageAge.available,
    version_age_risk: versionAge.available,
    release_burstiness_risk: releaseBurstiness.available,
    unusual_tag_risk: unusualTag.available,
    lifecycle_script_risk: scriptRisk.available,
    executable_flag_risk: executableRisk.available,
    provenance_regression_risk: provenanceRegression.available,
    publisher_changed_risk: publisherChanged.available,
    maintainer_changed_risk: maintainerChanged.available,
    dependency_risk: dependencyRisk.available,
    name_similarity_risk: similarityRisk.available,
    hallucination_corpus_risk: corpusRisk.available,
    popularity_risk: popularityRisk.available,
    cve_risk: cveRisk.available
  };

  const completeness = EXPECTED_FEATURES.reduce((count, featureName) => count + (availability[featureName] ? 1 : 0), 0) / EXPECTED_FEATURES.length;

  return {
    featureVector,
    availability,
    completeness
  };
}