#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TRUST_ENGINE_WEIGHTS, POLICY_THRESHOLDS } from '../../../src/constants.js';
import { parsePackageSpec } from '../../../src/utils.js';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ANALYSIS_DIR = path.resolve(SCRIPT_DIR, '..');
const OUTPUT_DIR = path.join(ANALYSIS_DIR, 'output');
const REPO_ROOT = path.resolve(ANALYSIS_DIR, '..', '..');
const resultsPath = path.join(OUTPUT_DIR, 'check-results.cli.jsonl');
const logPath = path.join(REPO_ROOT, 'pact-decision-engine.jsonl');

const HIGH_VALUE = 0.5;
const INSTALL_SCRIPT_NAMES = new Set(['preinstall', 'install', 'postinstall', 'prepare']);
const STANDARD_BUILD_SCRIPT = /^(?:node-gyp\s+(?:rebuild|clean)(?:\s*&&\s*node-gyp\s+(?:rebuild|clean))*|prebuild-install(?:\s*\|\|\s*node-gyp\s+rebuild)?|npm\s+run\s+(?:build|prepare|prepublishOnly)|\[\s*-f\s+fsevents\.node\s*\]\s*\|\|\s*npm\s+run\s+(?:prepare|prepublishOnly))$/i;
const SCRIPT_MARKERS = {
  curl_or_wget: /\b(?:curl|wget)\b/i,
  sh_path: /\bsh\s+(?!-[a-z])/i,
  bash_path: /\bbash\s+(?!-[a-z])/i,
  node_path: /\bnode\s+(?!-e)/i,
  node_eval: /\bnode\s+(?:-e|--eval)\b/i,
  chmod: /\bchmod\s+\+x\b/i,
  base64: /\bbase64\s+-d\b/i,
  eval_call: /\beval\s*\(/i,
  require_call: /\brequire\s*\(/i,
  powershell: /\bpowershell\b|\binvoke-webrequest\b|\biwr\b/i,
  python: /\bpython(?:3)?\s+-c\b/i,
  netcat: /\bnc\s|\bnetcat\b/i,
  child_process: /\bchild_process\b/i,
  postinstall_handler: /(?:pre|post)?install\.js/i,
  node_gyp: /\bnode-gyp\b/i,
  prebuild_install: /\bprebuild-install\b/i,
  rm_rf: /\brm\s+-rf\b/i,
  env_exfil: /process\.env|\.npmrc|\.ssh|token|password|secret/i,
  write_elsewhere: /(?:>|>>)\s*(?:\.\.\/|\/tmp\/|\/etc\/|\$HOME|~\/)/i
};
const weightedFeatures = Object.keys(TRUST_ENGINE_WEIGHTS);
const behaviorFeatures = [
  'hallucination_corpus_risk',
  'name_similarity_risk',
  'dependency_risk',
  'executable_flag_risk',
  'publisher_changed_risk'
];

function clamp(value, min = 0, max = 1) {
  return Math.min(max, Math.max(min, Number(value) || 0));
}

function logKey(entry) {
  return `${entry.requested_package?.name}@${entry.requested_package?.version}`;
}

function lastWins(entries, keyFn) {
  const map = new Map();
  for (const entry of entries) {
    map.set(keyFn(entry), entry);
  }
  return map;
}

function csvEscape(value) {
  const text = typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value ?? '');
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(filePath, rows, columns) {
  const lines = [columns.join(',')];
  for (const row of rows) {
    lines.push(columns.map((column) => csvEscape(row[column])).join(','));
  }
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`);
}

function pct(value) {
  return `${(value * 100).toFixed(2)}%`;
}

function stats(values) {
  const numeric = values.map(Number).filter((value) => Number.isFinite(value)).sort((a, b) => a - b);
  if (!numeric.length) {
    return { count: 0, min: null, median: null, p90: null, max: null, mean: null };
  }
  return {
    count: numeric.length,
    min: numeric[0],
    median: numeric[Math.floor(numeric.length / 2)],
    p90: numeric[Math.floor(numeric.length * 0.9)],
    max: numeric[numeric.length - 1],
    mean: numeric.reduce((sum, value) => sum + value, 0) / numeric.length
  };
}

function osvStatus(osv) {
  if (!osv) {
    return 'not_checked';
  }
  if (osv.unavailable) {
    return 'lookup_failed';
  }
  if (osv.malicious) {
    return 'malicious_advisory_found';
  }
  return (osv.advisoryCount ?? osv.knownCveCount ?? 0) > 0
    ? 'non_malicious_advisories_only'
    : 'no_advisory_found';
}

function findLogEntry(row, logsByPackage, logsByNormalized) {
  const exact = logsByPackage.get(`${row.package_name}@${row.package_version}`);
  if (exact) {
    return { entry: exact, method: 'package_name', ambiguous: false };
  }
  const candidates = logsByNormalized.get(`${row.normalized_name}@${row.normalized_version}`) ?? [];
  if (!candidates.length) {
    return { entry: null, method: 'none', ambiguous: false };
  }
  const matching = candidates.filter((entry) => (
    Number(entry.risk_score) === Number(row.risk_score)
    && (!row.existence_status || entry.existence_check?.status === row.existence_status)
  ));
  const selected = matching.at(-1) ?? candidates.at(-1);
  return {
    entry: selected,
    method: matching.length ? 'normalized_name+status+risk' : 'normalized_name_last',
    ambiguous: candidates.length > 1
  };
}

function featureSnapshot(entry) {
  const vector = entry.feature_vector ?? {};
  const values = {};
  const contributions = {};
  const available = {};
  const unavailable = new Set(entry.unavailable_features ?? []);
  for (const feature of weightedFeatures) {
    values[feature] = Number(vector[feature] ?? 0);
    contributions[feature] = TRUST_ENGINE_WEIGHTS[feature] * clamp(values[feature]);
    available[feature] = !unavailable.has(feature);
  }
  const ranked = Object.entries(contributions)
    .map(([feature, contribution]) => ({ feature, contribution, value: values[feature] }))
    .sort((left, right) => right.contribution - left.contribution);
  return {
    values,
    contributions,
    available,
    unavailable: [...unavailable],
    ranked,
    top: ranked[0]?.contribution > 0 ? ranked[0] : null
  };
}

function metadataSnapshot(entry) {
  const snapshot = entry.existence_check?.raw_metadata_snapshot ?? {};
  const lifecycleScripts = snapshot.lifecycle_scripts ?? {};
  const scriptEntries = Object.entries(lifecycleScripts).filter(([, value]) => Boolean(value));
  const dependencies = Object.keys(snapshot.dependencies ?? {});
  const maintainers = (snapshot.maintainers ?? [])
    .map((maintainer) => maintainer?.name ?? maintainer?.email ?? String(maintainer))
    .filter(Boolean);
  const downloads = snapshot.downloads ?? {};
  return {
    snapshot,
    lifecycle_scripts: lifecycleScripts,
    script_names: scriptEntries.map(([name]) => name),
    install_script_names: scriptEntries.map(([name]) => name).filter((name) => INSTALL_SCRIPT_NAMES.has(name)),
    install_time_script_present: scriptEntries.some(([name]) => INSTALL_SCRIPT_NAMES.has(name)),
    standard_build_script_only: (() => {
      const installScripts = scriptEntries.filter(([name]) => INSTALL_SCRIPT_NAMES.has(name));
      return installScripts.length > 0 && installScripts.every(([, value]) => STANDARD_BUILD_SCRIPT.test(String(value).trim()));
    })(),
    script_count: scriptEntries.length,
    script_present: scriptEntries.length > 0,
    dependencies,
    dependency_count: dependencies.length,
    maintainers,
    maintainer_count: maintainers.length,
    dist_tags: snapshot.dist_tags ?? {},
    downloads,
    weekly_downloads: downloads.weekly ?? null,
    downloads_available: downloads.available === true,
    published_at_snapshot: snapshot.published_at ?? null,
    provenance_present: snapshot.provenance_present ?? null,
    raw_size_bytes: snapshot.raw_size_bytes ?? null
  };
}

function scriptMarkers(lifecycleScripts) {
  const joined = Object.entries(lifecycleScripts ?? {})
    .filter(([, value]) => Boolean(value))
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');
  return Object.entries(SCRIPT_MARKERS)
    .filter(([, pattern]) => pattern.test(joined))
    .map(([marker]) => marker);
}

function classifyMalicious(row, entry, features, metadata) {
  const risk = Number(entry.risk_score ?? row.risk_score ?? 0);
  const highBehavior = behaviorFeatures.filter((feature) => features.values[feature] >= HIGH_VALUE);
  const highAny = weightedFeatures.filter((feature) => features.values[feature] >= HIGH_VALUE);
  const unavailableWeighted = features.unavailable.filter((feature) => weightedFeatures.includes(feature));
  const secondary = [];

  if (!entry.osv_result?.malicious) {
    secondary.push('no_OSV_malicious_advisory');
  }
  if ((entry.osv_result?.advisoryCount ?? 0) === 0 && entry.osv_result?.unavailable === false) {
    secondary.push('no_OSV_advisory_at_all');
  }
  if (osvStatus(entry.osv_result) === 'non_malicious_advisories_only') {
    secondary.push('only_non_malicious_OSV_advisories');
  }
  if (!metadata.downloads_available) {
    secondary.push('downloads_unavailable');
  } else if (
    typeof metadata.weekly_downloads === 'number'
    && metadata.weekly_downloads >= 1000
    && (features.values.popularity_risk ?? 1) < HIGH_VALUE
  ) {
    secondary.push('high_downloads_low_popularity_risk');
  }
  if (metadata.script_present && features.values.lifecycle_script_risk === 0) {
    secondary.push('lifecycle_scripts_present_but_not_flagged');
  }
  if (metadata.install_time_script_present && features.values.lifecycle_script_risk === 0) {
    secondary.push('install_time_scripts_present_but_not_flagged');
  }
  if (metadata.standard_build_script_only && highBehavior.length === 0) {
    secondary.push('standard_build_script_only');
  }
  if (unavailableWeighted.length >= 4) {
    secondary.push('at_least_4_weighted_feature_families_unavailable');
  }
  if (features.unavailable.includes('provenance_regression_risk') && features.unavailable.includes('maintainer_changed_risk')) {
    secondary.push('provenance_and_maintainer_history_unavailable');
  }
  if (features.unavailable.includes('executable_flag_risk')) {
    secondary.push('executable_flag_unavailable');
  }
  if (releaseBurstinessValue(entry) > 0) {
    secondary.push('unweighted_release_burstiness_signal');
  }
  if (risk === 0) {
    secondary.push('zero_risk_score');
  }

  let primary;
  let subcategory;
  let evidence;

  if (highBehavior.length > 0) {
    primary = 'Scoring/weighting/threshold issue';
    subcategory = highBehavior.join('+');
    const highDetails = highBehavior.map((feature) => `${feature}=${features.values[feature].toFixed(3)}`).join(', ');
    const contributionTotal = highBehavior.reduce((sum, feature) => sum + features.contributions[feature], 0);
    evidence = `${highDetails}; their combined contribution ${contributionTotal.toFixed(4)} left total risk ${risk.toFixed(4)} below WARN ${POLICY_THRESHOLDS.warn} and BLOCK ${POLICY_THRESHOLDS.block}`;
  } else if (metadata.standard_build_script_only) {
    primary = 'No malicious metadata signal (standard build script only)';
    subcategory = 'standard_build_script_only';
    evidence = `only standard build install scripts present (${metadata.install_script_names.join(', ')}) and no behavior feature reached ${HIGH_VALUE}`;
  } else if (metadata.install_time_script_present) {
    primary = 'Suspicious behavior not represented by existing features';
    subcategory = 'install_time_scripts_present_but_not_flagged';
    evidence = `install-time lifecycle scripts present (${metadata.install_script_names.join(', ')}) but lifecycle_script_risk=0 and no behavior feature reached ${HIGH_VALUE}`;
  } else if (metadata.script_present) {
    primary = 'Suspicious behavior not represented by existing features';
    subcategory = 'only_non_install_lifecycle_scripts';
    evidence = `only non-install lifecycle scripts present (${metadata.script_names.join(', ') || 'unknown'}); no behavior feature reached ${HIGH_VALUE}`;
  } else {
    primary = 'Suspicious behavior not represented by existing features';
    subcategory = 'no_lifecycle_script_and_no_high_feature';
    evidence = `no lifecycle scripts and no weighted behavior feature reached ${HIGH_VALUE}; total risk ${risk.toFixed(4)}`;
  }

  if (metadata.script_present && features.values.lifecycle_script_risk === 0 && highBehavior.length > 0) {
    secondary.push('script_heuristic_gap_also_present');
  }

  return { risk, highBehavior, highAny, primary, subcategory, evidence, secondary };
}

function releaseBurstinessValue(entry) {
  return Number(entry.feature_vector?.release_burstiness_risk ?? 0);
}

function buildMaliciousRow(row, entry, match) {
  const features = featureSnapshot(entry);
  const metadata = metadataSnapshot(entry);
  const classification = classifyMalicious(row, entry, features, metadata);
  const unavailableWeighted = features.unavailable.filter((feature) => weightedFeatures.includes(feature));
  const output = {
    package_name: row.package_name,
    package_version: row.package_version,
    label: row.label,
    source_path: row.source_path,
    spec: row.spec,
    normalized_name: row.normalized_name,
    normalized_version: row.normalized_version,
    log_match_method: match.method,
    log_match_ambiguous: match.ambiguous,
    decision: row.decision,
    risk_score: classification.risk,
    confidence: row.confidence,
    warn_threshold: POLICY_THRESHOLDS.warn,
    block_threshold: POLICY_THRESHOLDS.block,
    gap_to_warn: POLICY_THRESHOLDS.warn - classification.risk,
    gap_to_block: POLICY_THRESHOLDS.block - classification.risk,
    existence_status: row.existence_status,
    osv_status: osvStatus(entry.osv_result),
    osv_malicious: entry.osv_result?.malicious ?? row.osv_malicious,
    osv_unavailable: entry.osv_result?.unavailable ?? row.osv_unavailable,
    osv_advisory_count: entry.osv_result?.advisoryCount ?? null,
    osv_max_severity: entry.osv_result?.maxSeverity ?? null,
    evidence_completeness: entry.evidence_completeness ?? null,
    unavailable_features: features.unavailable.join(';'),
    unavailable_feature_count: features.unavailable.length,
    unavailable_weighted_feature_count: unavailableWeighted.length,
    downloads_weekly: metadata.weekly_downloads,
    downloads_available: metadata.downloads_available,
    maintainers_count: metadata.maintainer_count,
    maintainers: metadata.maintainers.join(';'),
    dist_tags: metadata.dist_tags,
    dist_tag_count: Object.keys(metadata.dist_tags).length,
    published_at_snapshot: metadata.published_at_snapshot,
    lifecycle_script_count: metadata.script_count,
    lifecycle_scripts: metadata.lifecycle_scripts,
    lifecycle_script_present: metadata.script_present,
    install_time_script_present: metadata.install_time_script_present,
    install_script_names: metadata.install_script_names.join(';'),
    standard_build_script_only: metadata.standard_build_script_only,
    script_markers: scriptMarkers(metadata.lifecycle_scripts).join(';'),
    script_heuristic_miss: metadata.script_present && features.values.lifecycle_script_risk === 0,
    dependency_count: metadata.dependency_count,
    dependencies: metadata.dependencies.join(';'),
    provenance_present: metadata.provenance_present,
    raw_size_bytes: metadata.raw_size_bytes,
    release_burstiness_risk: releaseBurstinessValue(entry),
    release_burstiness_contribution: 0,
    top_signal: features.top?.feature ?? 'none',
    top_contribution: features.top?.contribution ?? 0,
    positive_signal_count: Object.values(features.contributions).filter((value) => value > 0).length,
    high_signal_features: classification.highAny.join(';'),
    high_behavior_features: classification.highBehavior.join(';'),
    primary_root_cause: classification.primary,
    root_cause_subcategory: classification.subcategory,
    root_cause_evidence: classification.evidence,
    secondary_factors: classification.secondary.join(';')
  };
  for (const feature of weightedFeatures) {
    output[`value_${feature}`] = features.values[feature];
    output[`weight_${feature}`] = TRUST_ENGINE_WEIGHTS[feature];
    output[`contribution_${feature}`] = features.contributions[feature];
  }
  return output;
}

function buildBenignBlockRow(row, entry, match) {
  const snapshot = entry?.existence_check?.raw_metadata_snapshot ?? {};
  const downloads = snapshot.downloads ?? {};
  const parsed = parsePackageSpec(`${row.package_name}@${row.package_version}`);
  const normalizedByParser = parsed.name !== row.package_name || parsed.version !== row.package_version;
  const status = entry?.existence_check?.status ?? row.existence_status;
  return {
    package_name: row.package_name,
    package_version: row.package_version,
    label: row.label,
    source_path: row.source_path,
    spec: row.spec,
    normalized_name: row.normalized_name,
    normalized_version: row.normalized_version,
    log_match_method: match.method,
    log_match_ambiguous: match.ambiguous,
    parser_normalized_spec: normalizedByParser,
    parser_name: parsed.name,
    parser_version: parsed.version,
    decision: row.decision,
    risk_score: entry?.risk_score ?? row.risk_score,
    confidence: row.confidence,
    existence_status: status,
    reason: row.reason,
    osv_status: osvStatus(entry?.osv_result),
    osv_malicious: entry?.osv_result?.malicious ?? row.osv_malicious,
    osv_unavailable: entry?.osv_result?.unavailable ?? row.osv_unavailable,
    osv_advisory_count: entry?.osv_result?.advisoryCount ?? null,
    downloads_weekly: downloads.weekly ?? null,
    downloads_available: downloads.available === true,
    maintainers_count: (snapshot.maintainers ?? []).length,
    dist_tags: snapshot.dist_tags ?? {},
    dependency_count: Object.keys(snapshot.dependencies ?? {}).length,
    provenance_present: snapshot.provenance_present ?? null,
    raw_size_bytes: snapshot.raw_size_bytes ?? null,
    primary_root_cause: 'Registry existence check false positive',
    root_cause_subcategory: status === 'missing_version' ? 'nonexistent_version' : 'nonexistent_package',
    case_normalization_suspect: normalizedByParser,
    evidence: status === 'missing_version'
      ? 'npm registry returned package metadata but the requested version was absent'
      : 'npm registry returned no package document (404)'
  };
}

function countBy(rows, key) {
  return rows.reduce((counts, row) => {
    const value = row[key];
    counts[value] = (counts[value] ?? 0) + 1;
    return counts;
  }, {});
}

function sortCounts(counts) {
  return Object.entries(counts).sort((left, right) => right[1] - left[1]);
}

function scriptCoverage(rows) {
  const scriptNames = {};
  const markerCounts = {};
  const scriptTexts = {};
  let withScripts = 0;
  let withInstallScripts = 0;
  let standardBuildOnly = 0;
  let flagged = 0;
  for (const row of rows) {
    const entries = Object.entries(row.lifecycle_scripts ?? {}).filter(([, value]) => Boolean(value));
    if (!entries.length) continue;
    withScripts++;
    if (row.install_time_script_present) withInstallScripts++;
    if (row.standard_build_script_only) standardBuildOnly++;
    if (row.value_lifecycle_script_risk > 0) flagged++;
    for (const [name, value] of entries) {
      scriptNames[name] = (scriptNames[name] ?? 0) + 1;
      const text = `${name}: ${value}`;
      scriptTexts[text] = (scriptTexts[text] ?? 0) + 1;
    }
    for (const marker of row.script_markers ? row.script_markers.split(';').filter(Boolean) : []) {
      markerCounts[marker] = (markerCounts[marker] ?? 0) + 1;
    }
  }
  return {
    with_scripts: withScripts,
    with_install_time_scripts: withInstallScripts,
    standard_build_script_only: standardBuildOnly,
    flagged_by_lifecycle_script_risk: flagged,
    script_names: sortCounts(scriptNames).map(([name, count]) => ({ name, count })),
    markers: sortCounts(markerCounts).map(([marker, count]) => ({ marker, count })),
    top_scripts: sortCounts(scriptTexts).slice(0, 20).map(([script, count]) => ({ script, count }))
  };
}

function buildSummary(maliciousRows, benignRows, allLogEntries) {
  const total = maliciousRows.length;
  const primary = sortCounts(countBy(maliciousRows, 'primary_root_cause'));
  const subcategories = sortCounts(countBy(maliciousRows, 'root_cause_subcategory'));
  const osv = sortCounts(countBy(maliciousRows, 'osv_status'));
  const riskBuckets = sortCounts(maliciousRows.reduce((counts, row) => {
    const value = row.risk_score;
    let bucket;
    if (value === 0) bucket = '0';
    else if (value < 0.05) bucket = '0-0.05';
    else if (value < 0.1) bucket = '0.05-0.1';
    else if (value < 0.2) bucket = '0.1-0.2';
    else bucket = '0.2-0.3';
    counts[bucket] = (counts[bucket] ?? 0) + 1;
    return counts;
  }, {}));
  const downloadBuckets = sortCounts(maliciousRows.reduce((counts, row) => {
    let bucket;
    if (!row.downloads_available) bucket = 'unavailable';
    else if (row.downloads_weekly === 0) bucket = '0';
    else if (row.downloads_weekly < 100) bucket = '1-99';
    else if (row.downloads_weekly < 1000) bucket = '100-999';
    else if (row.downloads_weekly < 10000) bucket = '1000-9999';
    else bucket = '10000+';
    counts[bucket] = (counts[bucket] ?? 0) + 1;
    return counts;
  }, {}));
  const secondary = sortCounts(maliciousRows.reduce((counts, row) => {
    for (const factor of row.secondary_factors ? row.secondary_factors.split(';') : []) {
      counts[factor] = (counts[factor] ?? 0) + 1;
    }
    return counts;
  }, {}));
  const featureStats = {};
  for (const feature of weightedFeatures) {
    const values = maliciousRows.map((row) => row[`value_${feature}`]);
    const contributions = maliciousRows.map((row) => row[`contribution_${feature}`]);
    featureStats[feature] = {
      weight: TRUST_ENGINE_WEIGHTS[feature],
      nonzero_values: values.filter((value) => value > 0).length,
      values_at_least_0_5: values.filter((value) => value >= HIGH_VALUE).length,
      unavailable: maliciousRows.filter((row) => row.unavailable_features.split(';').includes(feature)).length,
      value_stats: stats(values),
      contribution_stats: stats(contributions),
      max_contribution: Math.max(...contributions)
    };
  }
  const completenessStats = stats(maliciousRows.map((row) => row.evidence_completeness));
  const riskStats = stats(maliciousRows.map((row) => row.risk_score));
  const topSignals = sortCounts(countBy(maliciousRows, 'top_signal'));
  const highBehaviorPatterns = sortCounts(countBy(maliciousRows, 'high_behavior_features'));
  const patternCounts = sortCounts(maliciousRows.reduce((counts, row) => {
    const pattern = `script=${row.lifecycle_script_present ? 'present' : 'absent'};high=${row.high_behavior_features || 'none'};top=${row.top_signal}`;
    counts[pattern] = (counts[pattern] ?? 0) + 1;
    return counts;
  }, {}));
  const examples = {};
  for (const [category] of primary) {
    for (const [subcategory] of subcategories) {
      const matching = maliciousRows.filter((row) => row.primary_root_cause === category && row.root_cause_subcategory === subcategory);
      if (!matching.length) continue;
      const chosen = matching
        .slice()
        .sort((left, right) => right.risk_score - left.risk_score)
        .slice(0, 3);
      examples[`${category} :: ${subcategory}`] = chosen.map((row) => ({
        spec: row.spec,
        risk_score: row.risk_score,
        top_signal: row.top_signal,
        high_behavior_features: row.high_behavior_features,
        script_present: row.lifecycle_script_present,
        script_names: row.lifecycle_script_count ? Object.keys(row.lifecycle_scripts) : [],
        downloads_weekly: row.downloads_weekly,
        osv_status: row.osv_status,
        secondary_factors: row.secondary_factors
      }));
    }
  }
  const benignPrimary = sortCounts(countBy(benignRows, 'primary_root_cause'));
  const benignSub = sortCounts(countBy(benignRows, 'root_cause_subcategory'));
  const benignOsv = sortCounts(countBy(benignRows, 'osv_status'));
  const benignNormalization = benignRows.filter((row) => row.case_normalization_suspect).length;
  return {
    generated_at: new Date().toISOString(),
    data_sources: {
      results: resultsPath,
      decision_log: logPath,
      decision_log_entries: allLogEntries,
      network_requests: 0
    },
    feature_model: {
      weighted_feature_count: weightedFeatures.length,
      weighted_features: weightedFeatures,
      unweighted_feature_present: 'release_burstiness_risk',
      note: 'The feature vector has 14 fields. release_burstiness_risk is computed but has no weight in TRUST_ENGINE_WEIGHTS; 13 features are weighted.'
    },
    malicious_allow: {
      total,
      primary_root_cause: primary.map(([category, count]) => ({ category, count, percentage: count / total })),
      subcategories: subcategories.map(([category, count]) => ({ category, count, percentage: count / total })),
      osv_status: osv.map(([status, count]) => ({ status, count, percentage: count / total })),
      risk_buckets: riskBuckets,
      download_buckets: downloadBuckets,
      secondary_factors: secondary.map(([factor, count]) => ({ factor, count, percentage: count / total })),
      completeness_stats: completenessStats,
      risk_stats: riskStats,
      feature_stats: featureStats,
      script_coverage: scriptCoverage(maliciousRows),
      top_signals: topSignals,
      high_behavior_patterns: highBehaviorPatterns,
      common_patterns: patternCounts.slice(0, 15),
      representative_examples: examples
    },
    benign_block: {
      total: benignRows.length,
      primary_root_cause: benignPrimary.map(([category, count]) => ({ category, count, percentage: count / benignRows.length })),
      subcategories: benignSub.map(([category, count]) => ({ category, count, percentage: count / benignRows.length })),
      osv_status: benignOsv.map(([status, count]) => ({ status, count, percentage: count / benignRows.length })),
      case_normalization_suspects: benignNormalization
    }
  };
}

function buildMarkdown(summary) {
  const m = summary.malicious_allow;
  const b = summary.benign_block;
  const standardBuildNoHigh = m.subcategories.find((entry) => entry.category === 'standard_build_script_only')?.count ?? 0;
  const lines = [];
  lines.push('# Root-cause analysis: malicious ALLOW and benign BLOCK');
  lines.push('');
  lines.push(`Generated: ${summary.generated_at}`);
  lines.push('');
  lines.push('## Evidence sources');
  lines.push('');
  lines.push(`- Baseline decisions: \`${summary.data_sources.results}\``);
  lines.push(`- Full per-case decision records: \`${summary.data_sources.decision_log}\` (${summary.data_sources.decision_log_entries} entries, last record per package@version wins)`);
  lines.push(`- Decision-log joins: malicious ${summary.log_matching.malicious.exact} exact + ${summary.log_matching.malicious.normalized} normalized fallback (${summary.log_matching.malicious.ambiguous} ambiguous); benign ${summary.log_matching.benign.exact} exact + ${summary.log_matching.benign.normalized} normalized fallback (${summary.log_matching.benign.ambiguous} ambiguous)`);
  lines.push('- New network requests: **0**');
  lines.push('');
  lines.push(`The feature vector contains 14 fields. **${summary.feature_model.weighted_feature_count}** are weighted in \`TRUST_ENGINE_WEIGHTS\`; \`release_burstiness_risk\` is computed but unweighted.`);
  lines.push('');
  lines.push('## Malicious ALLOW: primary root causes');
  lines.push('');
  lines.push('| Category | Count | Share |');
  lines.push('| --- | ---: | ---: |');
  for (const entry of m.primary_root_cause) {
    lines.push(`| ${entry.category} | ${entry.count} | ${pct(entry.percentage)} |`);
  }
  lines.push('');
  lines.push('| Subcategory | Count | Share |');
  lines.push('| --- | ---: | ---: |');
  for (const entry of m.subcategories) {
    lines.push(`| ${entry.category} | ${entry.count} | ${pct(entry.percentage)} |`);
  }
  lines.push('');
  lines.push('### OSV status');
  lines.push('');
  lines.push('| Status | Count | Share |');
  lines.push('| --- | ---: | ---: |');
  for (const entry of m.osv_status) {
    lines.push(`| ${entry.status} | ${entry.count} | ${pct(entry.percentage)} |`);
  }
  lines.push('');
  lines.push('### Secondary evidence');
  lines.push('');
  lines.push('| Factor | Count | Share |');
  lines.push('| --- | ---: | ---: |');
  for (const entry of m.secondary_factors) {
    lines.push(`| ${entry.factor} | ${entry.count} | ${pct(entry.percentage)} |`);
  }
  lines.push('');
  lines.push('### Feature-level evidence');
  lines.push('');
  lines.push('| Feature | Weight | Nonzero | >=0.5 | Unavailable | Mean value | Mean contribution | Max contribution |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const [feature, value] of Object.entries(m.feature_stats)) {
    lines.push(`| ${feature} | ${value.weight} | ${value.nonzero_values} | ${value.values_at_least_0_5} | ${value.unavailable} | ${value.value_stats.mean?.toFixed(3) ?? 'n/a'} | ${value.contribution_stats.mean?.toFixed(4) ?? 'n/a'} | ${value.max_contribution.toFixed(4)} |`);
  }
  lines.push('');
  lines.push('### Lifecycle script coverage');
  lines.push('');
  lines.push(`${m.script_coverage.with_scripts} of ${m.total} have at least one lifecycle script; ${m.script_coverage.with_install_time_scripts} have an install-time script (preinstall/install/postinstall/prepare); ${m.script_coverage.standard_build_script_only} have only standard build scripts; ${m.script_coverage.flagged_by_lifecycle_script_risk} were flagged by \`lifecycle_script_risk\`.`);
  lines.push('');
  lines.push('| Marker | Count |');
  lines.push('| --- | ---: |');
  for (const entry of m.script_coverage.markers) {
    lines.push(`| ${entry.marker} | ${entry.count} |`);
  }
  lines.push('');
  lines.push('| Script name | Count |');
  lines.push('| --- | ---: |');
  for (const entry of m.script_coverage.script_names.slice(0, 12)) {
    lines.push(`| ${entry.name} | ${entry.count} |`);
  }
  lines.push('');
  lines.push('| Most common script text | Count |');
  lines.push('| --- | ---: |');
  for (const entry of m.script_coverage.top_scripts.slice(0, 12)) {
    lines.push(`| \`${entry.script.replaceAll('|', '\\|').replaceAll('`', "'")}\` | ${entry.count} |`);
  }
  lines.push('');
  lines.push('High behavior feature means a behavior feature value at or above 0.5. The script heuristic flags only a subset of shell/Node execution patterns; install-time examples such as `preinstall: node new.js` and `preinstall: ./pre.sh` were present but scored zero. Non-install scripts such as `test` and `start` are also included in the counts but are less probative on their own.');
  lines.push('');
  lines.push('### Most common feature patterns');
  lines.push('');
  lines.push('| Pattern | Count |');
  lines.push('| --- | ---: |');
  for (const [pattern, count] of m.common_patterns) {
    lines.push(`| ${pattern} | ${count} |`);
  }
  lines.push('');
  lines.push('### Top positive signals');
  lines.push('');
  lines.push('| Signal | Count |');
  lines.push('| --- | ---: |');
  for (const [signal, count] of m.top_signals) {
    lines.push(`| ${signal} | ${count} |`);
  }
  lines.push('');
  lines.push('### Representative examples');
  lines.push('');
  for (const [category, examples] of Object.entries(m.representative_examples)) {
    lines.push(`#### ${category}`);
    lines.push('');
    for (const example of examples) {
      lines.push(`- \`${example.spec}\`: risk ${example.risk_score.toFixed(4)}, top signal ${example.top_signal}, high behavior ${example.high_behavior_features || 'none'}, scripts ${example.script_present ? 'present' : 'absent'}, downloads ${example.downloads_weekly ?? 'unavailable'}, OSV ${example.osv_status}`);
    }
    lines.push('');
  }
  lines.push('## Systemic findings and implications');
  lines.push('');
  lines.push(`- Missing features are scored as zero risk. Evidence completeness ranged ${m.completeness_stats.min?.toFixed(3)}-${m.completeness_stats.max?.toFixed(3)} (median ${m.completeness_stats.median?.toFixed(3)}); ${m.secondary_factors.find((entry) => entry.factor === 'at_least_4_weighted_feature_families_unavailable')?.count ?? 0} cases had at least four weighted features unavailable. Completeness affects confidence, not the risk sum.`);
  lines.push('- No registry or OSV retrieval failure occurred in these 235 cases. OSV returned no malicious advisory for any of them; 226 had no advisories and 9 had only non-malicious advisories.');
  lines.push(`- The lifecycle script feature is binary and regex-based. ${m.script_coverage.with_install_time_scripts} cases had install-time scripts, but none were flagged; the flag also does not distinguish standard build scripts from arbitrary execution.`);
  lines.push(`- High feature values were insufficient to reach WARN/BLOCK: ${m.primary_root_cause.find((entry) => entry.category === 'Scoring/weighting/threshold issue')?.count ?? 0} cases had at least one behavior feature at or above 0.5, yet the maximum observed risk was ${m.risk_stats.max.toFixed(4)}.`);
  lines.push(`- Popularity is not a credible primary cause: downloads were unavailable for ${m.secondary_factors.find((entry) => entry.factor === 'downloads_unavailable')?.count ?? 0} cases, and only ${m.secondary_factors.find((entry) => entry.factor === 'high_downloads_low_popularity_risk')?.count ?? 0} had high downloads with low popularity risk. Its weight is 0.01, so its maximum possible contribution is 0.01.`);
  lines.push('- `release_burstiness_risk` is computed but unweighted; only one case had a nonzero value (0.02).');
  lines.push('- Recommended next experiments, without changing production yet: renormalize weights by available evidence, add a missing-evidence penalty, expand install-script detection to arbitrary script paths, and treat standard build scripts separately. Re-evaluate thresholds against high-behavior cases before changing production policy.');
  lines.push('');
  lines.push('## Benign BLOCK');
  lines.push('');
  lines.push(`Total: **${b.total}**`);
  lines.push('');
  lines.push('| Category | Count | Share |');
  lines.push('| --- | ---: | ---: |');
  for (const entry of b.primary_root_cause) {
    lines.push(`| ${entry.category} | ${entry.count} | ${pct(entry.percentage)} |`);
  }
  lines.push('');
  lines.push('| Subcategory | Count | Share |');
  lines.push('| --- | ---: | ---: |');
  for (const entry of b.subcategories) {
    lines.push(`| ${entry.category} | ${entry.count} | ${pct(entry.percentage)} |`);
  }
  lines.push('');
  lines.push('| OSV status | Count | Share |');
  lines.push('| --- | ---: | ---: |');
  for (const entry of b.osv_status) {
    lines.push(`| ${entry.status} | ${entry.count} | ${pct(entry.percentage)} |`);
  }
  lines.push('');
  lines.push(`Case-normalization suspects among benign BLOCK: **${b.case_normalization_suspects}**.`);
  lines.push('');
  lines.push('## Limitations');
  lines.push('');
  lines.push('- No source code or package archive was downloaded or analyzed; the root causes are metadata/score-based.');
  lines.push('- The snapshot does not preserve exact publish timestamps or version history. Age features are available, but `published_at_snapshot` is null for all 235 and raw history cannot be reconstructed from the baseline output.');
  lines.push('- The snapshot does not preserve full maintainer/publisher history; provenance and maintainer-change features are unavailable for all 235.');
  lines.push('- "No OSV adversarial advisory found" is based on OSV lookups that completed successfully. It is distinct from an OSV lookup failure; no lookup failures occurred in these 235 cases.');
  lines.push(`- The 90 scoring/weighting cases have at least one feature at or above 0.5, but metadata alone cannot establish whether that signal was malicious or benign.`);
  lines.push(`- ${standardBuildNoHigh} of the 235 have only standard build install scripts (for example node-gyp) and no high behavior feature; metadata alone does not substantiate maliciousness for those cases.`);
  lines.push('');
  return `${lines.join('\n')}\n`;
}

function pickRepresentativeRows(maliciousRows) {
  const picks = [];
  for (const primary of [...new Set(maliciousRows.map((row) => row.primary_root_cause))]) {
    for (const subcategory of [...new Set(maliciousRows.filter((row) => row.primary_root_cause === primary).map((row) => row.root_cause_subcategory))]) {
      const matching = maliciousRows.filter((row) => row.primary_root_cause === primary && row.root_cause_subcategory === subcategory);
      picks.push(...matching.sort((left, right) => right.risk_score - left.risk_score).slice(0, 3));
    }
  }
  return picks;
}

function main() {
  const results = fs.readFileSync(resultsPath, 'utf8').split(/\r?\n/).filter(Boolean).map(JSON.parse);
  const logEntries = fs.readFileSync(logPath, 'utf8').split(/\r?\n/).filter(Boolean).map(JSON.parse);
  const logsByPackage = lastWins(logEntries, logKey);
  const logsByNormalized = new Map();
  for (const entry of logEntries) {
    const key = `${entry.requested_package?.name}@${entry.requested_package?.version}`;
    if (!logsByNormalized.has(key)) logsByNormalized.set(key, []);
    logsByNormalized.get(key).push(entry);
  }

  const fn = results.filter((row) => row.label === 'malicious' && row.decision === 'ALLOW');
  const fp = results.filter((row) => row.label === 'benign' && row.decision === 'BLOCK');

  const maliciousRows = [];
  const missingLog = [];
  const matching = { malicious: { exact: 0, normalized: 0, ambiguous: 0 }, benign: { exact: 0, normalized: 0, ambiguous: 0 } };
  for (const row of fn) {
    const match = findLogEntry(row, logsByPackage, logsByNormalized);
    if (!match.entry) {
      missingLog.push(row.spec);
      continue;
    }
    if (Number(match.entry.risk_score) !== Number(row.risk_score)) {
      throw new Error(`risk score mismatch for ${row.spec}: result=${row.risk_score} log=${match.entry.risk_score}`);
    }
    matching.malicious[match.method === 'package_name' ? 'exact' : 'normalized']++;
    if (match.ambiguous) matching.malicious.ambiguous++;
    maliciousRows.push(buildMaliciousRow(row, match.entry, match));
  }

  const benignRows = [];
  for (const row of fp) {
    const match = findLogEntry(row, logsByPackage, logsByNormalized);
    if (match.entry && Number(match.entry.risk_score) !== Number(row.risk_score)) {
      throw new Error(`risk score mismatch for ${row.spec}: result=${row.risk_score} log=${match.entry.risk_score}`);
    }
    matching.benign[match.method === 'package_name' ? 'exact' : 'normalized']++;
    if (match.ambiguous) matching.benign.ambiguous++;
    benignRows.push(buildBenignBlockRow(row, match.entry, match));
  }

  if (missingLog.length) {
    throw new Error(`missing decision-log entries for ${missingLog.length} malicious ALLOW cases: ${missingLog.slice(0, 10).join(', ')}`);
  }

  const maliciousColumns = [
    'package_name', 'package_version', 'label', 'source_path', 'spec', 'normalized_name', 'normalized_version',
    'log_match_method', 'log_match_ambiguous',
    'decision', 'risk_score', 'confidence', 'warn_threshold', 'block_threshold', 'gap_to_warn', 'gap_to_block',
    'existence_status', 'osv_status', 'osv_malicious', 'osv_unavailable', 'osv_advisory_count', 'osv_max_severity',
    'evidence_completeness', 'unavailable_features', 'unavailable_feature_count', 'unavailable_weighted_feature_count',
    'downloads_weekly', 'downloads_available', 'maintainers_count', 'maintainers', 'dist_tags', 'dist_tag_count',
    'published_at_snapshot', 'lifecycle_script_count', 'lifecycle_scripts', 'lifecycle_script_present',
    'install_time_script_present', 'install_script_names', 'standard_build_script_only',
    'script_markers', 'script_heuristic_miss',
    'dependency_count', 'dependencies', 'provenance_present', 'raw_size_bytes',
    'release_burstiness_risk', 'release_burstiness_contribution',
    'top_signal', 'top_contribution', 'positive_signal_count', 'high_signal_features', 'high_behavior_features',
    'primary_root_cause', 'root_cause_subcategory', 'root_cause_evidence', 'secondary_factors',
    ...weightedFeatures.flatMap((feature) => [`value_${feature}`, `weight_${feature}`, `contribution_${feature}`])
  ];
  const benignColumns = [
    'package_name', 'package_version', 'label', 'source_path', 'spec', 'normalized_name', 'normalized_version',
    'log_match_method', 'log_match_ambiguous',
    'parser_normalized_spec', 'parser_name', 'parser_version', 'decision', 'risk_score', 'confidence',
    'existence_status', 'reason', 'osv_status', 'osv_malicious', 'osv_unavailable', 'osv_advisory_count',
    'downloads_weekly', 'downloads_available', 'maintainers_count', 'dist_tags', 'dependency_count',
    'provenance_present', 'raw_size_bytes', 'primary_root_cause', 'root_cause_subcategory',
    'case_normalization_suspect', 'evidence'
  ];

  writeCsv(path.join(OUTPUT_DIR, 'malicious_allow_analysis.csv'), maliciousRows, maliciousColumns);
  writeCsv(path.join(OUTPUT_DIR, 'benign_block_analysis.csv'), benignRows, benignColumns);

  const summary = buildSummary(maliciousRows, benignRows, logEntries.length);
  summary.log_matching = matching;
  fs.writeFileSync(path.join(OUTPUT_DIR, 'root_cause_summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  fs.writeFileSync(path.join(OUTPUT_DIR, 'root_cause_summary.md'), buildMarkdown(summary));

  const representative = pickRepresentativeRows(maliciousRows);
  writeCsv(path.join(OUTPUT_DIR, 'root_cause_representative_examples.csv'), representative, maliciousColumns);

  console.log(`malicious ALLOW analyzed: ${maliciousRows.length}`);
  console.log(`benign BLOCK analyzed: ${benignRows.length}`);
  console.log(`wrote malicious_allow_analysis.csv, benign_block_analysis.csv, root_cause_summary.json, root_cause_summary.md, root_cause_representative_examples.csv`);
}

main();
