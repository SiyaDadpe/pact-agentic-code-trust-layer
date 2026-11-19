import { createHash } from 'node:crypto';
import { checkOsv } from './connectors/osv.js';
import { fetchNpmPackage } from './connectors/npm.js';
import { extractFeatures } from './feature-extractor.js';
import { normalizeMetadata } from './metadata-normalizer.js';
import { preprocessRequest } from './preprocessor.js';
import { decidePackageRisk } from './decision-engine.js';
import { scoreWithRuleEngine } from './trust-engine.js';

function metadataSnapshot(rawMetadata, versionMetadata, downloads) {
  const rawJson = JSON.stringify(rawMetadata ?? {});
  return {
    sha256: createHash('sha256').update(rawJson).digest('hex'),
    package_name: rawMetadata?.name ?? null,
    selected_version: versionMetadata?.version ?? null,
    published_at: versionMetadata?.time ?? null,
    maintainers: rawMetadata?.maintainers ?? [],
    dist_tags: rawMetadata?.['dist-tags'] ?? {},
    lifecycle_scripts: versionMetadata?.scripts ?? {},
    dependencies: versionMetadata?.dependencies ?? {},
    provenance_present: Boolean(versionMetadata?.dist?.attestations ?? versionMetadata?.provenance ?? false),
    downloads,
    raw_size_bytes: Buffer.byteLength(rawJson)
  };
}

function buildShortCircuitDecision(action, reason, request, logSnapshot = {}) {
  const decision = {
    timestamp: new Date().toISOString(),
    requested_package: {
      name: request?.name ?? request?.full_name ?? '',
      version: request?.version ?? null,
      ecosystem: request?.ecosystem ?? 'npm'
    },
    existence_check: logSnapshot.existence_check ?? null,
    osv_result: logSnapshot.osv_result ?? null,
    feature_vector: logSnapshot.feature_vector ?? null,
    trust_engine_version: 'rule_v1',
    risk_score: logSnapshot.risk_score ?? (action === 'BLOCK' ? 1 : 0),
    decision: action,
    confidence: logSnapshot.confidence ?? (action === 'BLOCK' ? 1 : 0),
    reason,
    contributing_signals: logSnapshot.contributing_signals ?? []
  };

  return {
    decision,
    logEntry: {
      ...decision,
      existence_check: logSnapshot.existence_check ?? null,
      osv_result: logSnapshot.osv_result ?? null,
      feature_vector: logSnapshot.feature_vector ?? null
    }
  };
}

export async function analyzePackageRequest(input, options = {}) {
  const request = preprocessRequest(input);
  if (!request.valid) {
    const result = buildShortCircuitDecision('BLOCK', request.reason, request, {
      existence_check: { status: 'invalid_request' },
      confidence: 0
    });
    return { request, ...result };
  }

  let registryResult;
  try {
    registryResult = await fetchNpmPackage(request.full_name, request.version, { timeoutMs: options.timeoutMs });
  } catch (error) {
    const result = buildShortCircuitDecision('UNKNOWN', String(error.message ?? error), request, {
      existence_check: { status: 'registry_unavailable' },
      confidence: 0,
      risk_score: 0,
      contributing_signals: []
    });
    return {
      request,
      existenceCheck: { status: 'registry_unavailable', error: String(error.message ?? error) },
      ...result
    };
  }

  if (!registryResult.exists) {
    const result = buildShortCircuitDecision('BLOCK', 'blocked: nonexistent_package', request, {
      existence_check: { status: 'missing_package', raw_metadata_snapshot: null },
      confidence: 1,
      risk_score: 1,
      contributing_signals: [{ feature_name: 'nonexistent_package', contribution: 1 }]
    });
    return {
      request,
      existenceCheck: { status: 'missing_package' },
      registryResult,
      ...result
    };
  }

  if (request.version && !registryResult.versionExists) {
    const result = buildShortCircuitDecision('BLOCK', 'blocked: nonexistent_version', request, {
      existence_check: {
        status: 'missing_version',
        raw_metadata_snapshot: metadataSnapshot(registryResult.rawMetadata, registryResult.rawVersionMetadata, registryResult.downloads)
      },
      confidence: 1,
      risk_score: 1,
      contributing_signals: [{ feature_name: 'nonexistent_version', contribution: 1 }]
    });
    return {
      request,
      existenceCheck: { status: 'missing_version' },
      registryResult,
      ...result
    };
  }

  let osvResult;
  try {
    osvResult = await checkOsv(request.full_name, registryResult.resolvedVersion, request.ecosystem, {
      timeoutMs: options.timeoutMs
    });
  } catch (error) {
    const result = buildShortCircuitDecision('UNKNOWN', String(error.message ?? error), request, {
      existence_check: {
        status: 'exists',
        raw_metadata_snapshot: metadataSnapshot(registryResult.rawMetadata, registryResult.rawVersionMetadata, registryResult.downloads)
      },
      confidence: 0,
      risk_score: 0,
      contributing_signals: []
    });
    return {
      request,
      registryResult,
      osvResult: { unavailable: true, error: String(error.message ?? error) },
      ...result
    };
  }

  if (osvResult.unavailable) {
    const result = buildShortCircuitDecision('UNKNOWN', 'registry_or_osv_unavailable', request, {
      existence_check: {
        status: 'exists',
        raw_metadata_snapshot: metadataSnapshot(registryResult.rawMetadata, registryResult.rawVersionMetadata, registryResult.downloads)
      },
      osv_result: osvResult,
      confidence: 0,
      risk_score: 0,
      contributing_signals: []
    });
    return {
      request,
      registryResult,
      osvResult,
      ...result
    };
  }

  if (osvResult.malicious) {
    const result = buildShortCircuitDecision('BLOCK', 'blocked: known_malicious', request, {
      existence_check: {
        status: 'exists',
        raw_metadata_snapshot: metadataSnapshot(registryResult.rawMetadata, registryResult.rawVersionMetadata, registryResult.downloads)
      },
      osv_result: osvResult,
      confidence: 1,
      risk_score: 1,
      contributing_signals: [{ feature_name: 'known_malicious', contribution: 1 }]
    });
    return {
      request,
      registryResult,
      osvResult,
      ...result
    };
  }

  const normalizedMetadata = normalizeMetadata(
    registryResult.rawMetadata,
    registryResult.resolvedVersion,
    registryResult.resolvedTag,
    { ...request, downloads: registryResult.downloads }
  );
  const extracted = extractFeatures({ metadata: normalizedMetadata, request, osvResult });
  const scored = scoreWithRuleEngine(extracted.featureVector, extracted.availability);
  const decision = decidePackageRisk({
    riskScore: scored.value,
    breakdown: scored.breakdown,
    completeness: extracted.completeness,
    availability: extracted.availability,
    featureVector: extracted.featureVector,
    existenceCheck: {
      status: 'exists',
      raw_metadata_snapshot: metadataSnapshot(registryResult.rawMetadata, registryResult.rawVersionMetadata, registryResult.downloads),
      version_exists: registryResult.versionExists
    },
    osvResult
  });

  const structuredDecision = {
    timestamp: new Date().toISOString(),
    requested_package: {
      name: request.full_name,
      version: request.version,
      ecosystem: request.ecosystem
    },
    existence_check: {
      status: 'exists',
      version_exists: registryResult.versionExists
    },
    osv_result: osvResult,
    feature_vector: extracted.featureVector,
    trust_engine_version: 'rule_v1',
    risk_score: scored.value,
    decision: decision.action,
    confidence: decision.confidence,
    evidence_completeness: extracted.completeness,
    unavailable_features: Object.entries(extracted.availability)
      .filter(([, available]) => !available)
      .map(([featureName]) => featureName),
    reason: decision.reason,
    contributing_signals: decision.contributing_signals
  };

  const logEntry = {
    ...structuredDecision,
    existence_check: {
      status: 'exists',
      raw_metadata_snapshot: metadataSnapshot(registryResult.rawMetadata, registryResult.rawVersionMetadata, registryResult.downloads),
      version_exists: registryResult.versionExists
    },
    osv_result: osvResult,
    feature_vector: extracted.featureVector,
    evidence: {
      published_at: normalizedMetadata.publish_timestamp,
      first_published_at: normalizedMetadata.first_publish_timestamp,
      version_count: normalizedMetadata.version_publish_timestamps.length,
      downloads: normalizedMetadata.downloads,
      maintainer_changed: normalizedMetadata.maintainer_changed,
      maintainers_added: normalizedMetadata.maintainers_added,
      publisher_changed: normalizedMetadata.publisher_changed,
      feature_availability: extracted.availability
    }
  };

  return {
    request,
    registryResult,
    osvResult,
    normalizedMetadata,
    featureVector: extracted.featureVector,
    featureAvailability: extracted.availability,
    trustScore: scored,
    decision: structuredDecision,
    logEntry
  };
}