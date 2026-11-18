import { TRUST_ENGINE_WEIGHTS } from './constants.js';
import { clamp } from './utils.js';

export function scoreWithRuleEngine(featureVector, availability = {}) {
  const breakdown = [];
  let value = 0;

  for (const [featureName, weight] of Object.entries(TRUST_ENGINE_WEIGHTS)) {
    const featureValue = Number(featureVector?.[featureName] ?? 0);
    const contribution = weight * clamp(featureValue);
    value += contribution;
    breakdown.push({ feature_name: featureName, contribution, weight, feature_value: featureValue });
  }

  breakdown.sort((left, right) => right.contribution - left.contribution);

  const completeness = Object.keys(TRUST_ENGINE_WEIGHTS).reduce(
    (count, featureName) => count + (availability[featureName] === undefined
      ? (Number.isFinite(featureVector?.[featureName]) ? 1 : 0)
      : (availability[featureName] ? 1 : 0)),
    0
  ) / Object.keys(TRUST_ENGINE_WEIGHTS).length;

  return {
    value: clamp(value),
    breakdown,
    completeness
  };
}