import { DEFAULT_ECOSYSTEM, TOP_PACKAGE_CORPUS_LIMIT } from './constants.js';
import { hallucinationCorpus, popularPackages } from './corpus.js';
import { pickNearest, parsePackageSpec, isDistTag, normalizeText } from './utils.js';

function normalizeNameParts(name) {
  if (name.startsWith('@')) {
    const slashIndex = name.indexOf('/');
    if (slashIndex === -1) {
      return { scope: null, packageName: name };
    }
    return {
      scope: normalizeText(name.slice(0, slashIndex)),
      packageName: normalizeText(name.slice(slashIndex + 1))
    };
  }

  return { scope: null, packageName: normalizeText(name) };
}

export function preprocessRequest(request) {
  const ecosystem = normalizeText(request.ecosystem ?? DEFAULT_ECOSYSTEM);
  if (ecosystem !== DEFAULT_ECOSYSTEM) {
    return {
      valid: false,
      reason: 'unsupported_ecosystem',
      ecosystem
    };
  }

  const parsed = parsePackageSpec(request.spec ?? request.name ?? '');
  if (!parsed.valid) {
    return {
      valid: false,
      reason: parsed.reason,
      ecosystem
    };
  }

  const { scope, packageName } = normalizeNameParts(parsed.name);
  const requestedVersion = parsed.version;
  let resolvedTag = 'pinned';
  let resolvedViaUnpinnedTag = false;

  if (!requestedVersion) {
    resolvedTag = 'latest';
    resolvedViaUnpinnedTag = true;
  } else if (isDistTag(requestedVersion)) {
    resolvedTag = requestedVersion;
    resolvedViaUnpinnedTag = true;
  }

  const fullName = scope ? `${scope}/${packageName}` : packageName;
  const corpusLimit = popularPackages.slice(0, TOP_PACKAGE_CORPUS_LIMIT);
  const nearestPopular = pickNearest(fullName, corpusLimit);
  const nearestHallucination = pickNearest(fullName, hallucinationCorpus);

  return {
    valid: true,
    name: packageName,
    scope,
    full_name: fullName,
    version: requestedVersion,
    requested_version: requestedVersion,
    resolved_tag: resolvedTag,
    resolved_via_unpinned_tag: resolvedViaUnpinnedTag,
    ecosystem,
    nearest_popular_match: nearestPopular.nearest,
    nearest_popular_distance: nearestPopular.nearestDistance,
    nearest_hallucination_match: nearestHallucination.nearest,
    nearest_hallucination_distance: nearestHallucination.nearestDistance
  };
}