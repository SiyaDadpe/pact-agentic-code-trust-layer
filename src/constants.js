export const DEFAULT_ECOSYSTEM = 'npm';
export const PACKAGE_REGISTRY_BASE = 'https://registry.npmjs.org';
export const NPM_DOWNLOADS_BASE = 'https://api.npmjs.org/downloads/point/last-week';
export const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';
export const REGISTRY_TTL_MS = 15 * 60 * 1000;
export const DEFAULT_LOG_FILE = 'pact-decision-engine.jsonl';
export const PACKAGE_AGE_THRESHOLD_DAYS = 90;
export const TOP_PACKAGE_CORPUS_LIMIT = 5000;

export const TRUST_ENGINE_WEIGHTS = {
  hallucination_corpus_risk: 0.18,
  lifecycle_script_risk: 0.17,
  name_similarity_risk: 0.14,
  package_age_risk: 0.1,
  dependency_risk: 0.1,
  provenance_regression_risk: 0.08,
  publisher_changed_risk: 0.06,
  maintainer_changed_risk: 0.05,
  executable_flag_risk: 0.03,
  version_age_risk: 0.04,
  unusual_tag_risk: 0.03,
  cve_risk: 0.01,
  popularity_risk: 0.01
};

export const POLICY_THRESHOLDS = {
  warn: 0.4,
  block: 0.75,
  newPackage: 0.75
};

export const EXPECTED_FEATURES = Object.keys(TRUST_ENGINE_WEIGHTS);

export const DIST_TAGS = new Set(['latest', 'next', 'beta', 'alpha', 'canary']);