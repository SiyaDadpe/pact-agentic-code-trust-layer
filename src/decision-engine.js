import { POLICY_THRESHOLDS } from './constants.js';
import { clamp } from './utils.js';

function topContributions(breakdown, limit = 5) {
  return [...(breakdown ?? [])].sort((left, right) => right.contribution - left.contribution).slice(0, limit);
}

function signalAgreementFactor(breakdown) {
  const top = topContributions(breakdown, 5).map((entry) => Math.max(entry.contribution, 0));
  const total = top.reduce((sum, value) => sum + value, 0);
  if (!total) {
    return 0.5;
  }

  const normalized = top.map((value) => value / total);
  const mean = 1 / normalized.length;
  const variance = normalized.reduce((sum, value) => sum + (value - mean) ** 2, 0) / normalized.length;
  return clamp(1 - variance * 8, 0.2, 1);
}

function allowConfidence(riskScore, completeness, breakdown) {
  const evidence = clamp(
    (0.6 * clamp(completeness ?? 0)) +
      (0.25 * signalAgreementFactor(breakdown)) +
      (0.15 * (1 - clamp(riskScore)))
  );

  return clamp(0.2 + evidence * 0.8);
}

function warnConfidence(riskScore, completeness, breakdown) {
  const evidence = clamp(
    (0.4 * clamp(completeness ?? 0)) +
      (0.3 * signalAgreementFactor(breakdown)) +
      (0.3 * (1 - clamp(riskScore)))
  );

  return clamp(0.15 + evidence * 0.7);
}

function blockConfidence(riskScore, completeness, breakdown) {
  const evidence = clamp(
    (0.4 * clamp(completeness ?? 0)) +
      (0.3 * signalAgreementFactor(breakdown)) +
      (0.3 * clamp(riskScore))
  );

  return clamp(0.2 + evidence * 0.75);
}

function applyPolicyRules({ riskScore, featureVector, availability, weeklyDownloads }) {
  const scriptRisk = featureVector?.lifecycle_script_risk ?? 0;
  const randomScriptFilenameRisk = featureVector?.random_script_filename_risk ?? 0;
  const established = typeof weeklyDownloads === 'number' && weeklyDownloads >= POLICY_THRESHOLDS.establishedWeeklyDownloads;
  const packageAgeRisk = featureVector?.package_age_risk ?? 0;
  const corpusRisk = featureVector?.hallucination_corpus_risk ?? 0;
  const similarityRisk = featureVector?.name_similarity_risk ?? 0;
  const popularityRisk = featureVector?.popularity_risk ?? 0;

  if (scriptRisk >= 1 && packageAgeRisk >= POLICY_THRESHOLDS.newPackage) {
    return {
      action: 'BLOCK',
      rule: 'new_package_with_install_script',
      reason: 'blocked: new package contains an install-time execution script'
    };
  }

  if (scriptRisk >= 1 && randomScriptFilenameRisk >= 1 && !established) {
    return {
      action: 'BLOCK',
      rule: 'install_script_runs_random_filename',
      reason: 'blocked: install-time script runs a randomly named file in a package that is not established'
    };
  }

  if (scriptRisk >= 1 && (similarityRisk >= POLICY_THRESHOLDS.typosquatSimilarity || corpusRisk >= POLICY_THRESHOLDS.typosquatSimilarity) && !established) {
    return {
      action: 'BLOCK',
      rule: 'typosquat_with_install_script',
      reason: 'blocked: install-time script in a package whose name imitates a popular or hallucinated package'
    };
  }

  if (scriptRisk >= 1) {
    return {
      action: 'WARN',
      rule: 'install_script_requires_review',
      reason: 'warned: package contains an install-time execution script'
    };
  }


  if (corpusRisk >= 1 && similarityRisk >= 0.5 && availability?.popularity_risk && popularityRisk >= 0.5) {
    return {
      action: 'BLOCK',
      rule: 'registered_hallucination_typosquat',
      reason: 'blocked: package matches a hallucination corpus and a popular-package typo pattern'
    };
  }

  if (corpusRisk >= 1 && similarityRisk >= 0.5) {
    return {
      action: 'WARN',
      rule: 'hallucination_typosquat_requires_review',
      reason: 'warned: package matches a hallucination corpus and a popular-package typo pattern'
    };
  }

  if (similarityRisk >= POLICY_THRESHOLDS.typosquatSimilarity && !established) {
    return {
      action: 'WARN',
      rule: 'possible_typosquat_requires_review',
      reason: 'warned: package name is one edit away from a popular package and the package is not established'
    };
  }

  if (riskScore >= POLICY_THRESHOLDS.block) {
    return { action: 'BLOCK', rule: null, reason: null };
  }

  if (riskScore >= POLICY_THRESHOLDS.warn) {
    return { action: 'WARN', rule: null, reason: null };
  }

  return { action: 'ALLOW', rule: null, reason: null };
}

function reasonFromSignals(action, signals) {
  if (!signals.length) {
    return `${action}: no strong signals available`;
  }

  const parts = signals.slice(0, 3).map((signal) => `${signal.feature_name}=${signal.contribution.toFixed(3)}`);
  return `${action}: ${parts.join(', ')}`;
}

export function decidePackageRisk({ riskScore, breakdown, completeness, availability, featureVector, existenceCheck, osvResult, weeklyDownloads }) {
  if (existenceCheck?.status === 'missing_package') {
    return {
      action: 'BLOCK',
      confidence: 1,
      risk_score: 1,
      reason: 'blocked: nonexistent_package',
      contributing_signals: [{ feature_name: 'nonexistent_package', contribution: 1 }]
    };
  }

  if (existenceCheck?.status === 'missing_version') {
    return {
      action: 'BLOCK',
      confidence: 1,
      risk_score: 1,
      reason: 'blocked: nonexistent_version',
      contributing_signals: [{ feature_name: 'nonexistent_version', contribution: 1 }]
    };
  }

  if (osvResult?.malicious) {
    return {
      action: 'BLOCK',
      confidence: 1,
      risk_score: 1,
      reason: 'blocked: known_malicious',
      contributing_signals: [{ feature_name: 'known_malicious', contribution: 1 }]
    };
  }

  const policy = applyPolicyRules({ riskScore, featureVector, availability, weeklyDownloads });
  const action = policy.action;

  const confidence =
    action === 'ALLOW'
      ? allowConfidence(riskScore, completeness, breakdown)
      : action === 'WARN'
        ? warnConfidence(riskScore, completeness, breakdown)
        : blockConfidence(riskScore, completeness, breakdown);
  const signals = topContributions(breakdown, 5);
  if (policy.rule) {
    signals.unshift({ feature_name: policy.rule, contribution: 1 });
  }

  return {
    action,
    confidence,
    risk_score: clamp(riskScore),
    reason: policy.reason ?? reasonFromSignals(action, signals),
    contributing_signals: signals,
    policy_rule: policy.rule
  };
}