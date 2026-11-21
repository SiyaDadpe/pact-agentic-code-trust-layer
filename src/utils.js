import { PACKAGE_AGE_THRESHOLD_DAYS, DIST_TAGS } from './constants.js';

export function clamp(value, min = 0, max = 1) {
  return Math.min(max, Math.max(min, value));
}

export function normalizeText(value) {
  return String(value ?? '').trim().toLowerCase().normalize('NFKC');
}

export function parsePackageSpec(spec) {
  const raw = normalizeText(spec);

  if (!raw) {
    return { valid: false, reason: 'empty_spec' };
  }

  if (
    raw.startsWith('git+') ||
    raw.startsWith('http://') ||
    raw.startsWith('https://') ||
    raw.startsWith('file:') ||
    raw.startsWith('.') ||
    raw.startsWith('/') ||
    raw.includes('://')
  ) {
    return { valid: false, reason: 'ambiguous_or_non_registry_spec' };
  }

  let name = raw;
  let version = null;

  if (raw.startsWith('@')) {
    const slashIndex = raw.indexOf('/');
    if (slashIndex === -1) {
      return { valid: false, reason: 'invalid_scoped_package' };
    }
    const atIndex = raw.lastIndexOf('@');
    if (atIndex > slashIndex) {
      name = raw.slice(0, atIndex);
      version = raw.slice(atIndex + 1) || null;
    }
  } else {
    const atIndex = raw.lastIndexOf('@');
    if (atIndex > 0) {
      name = raw.slice(0, atIndex);
      version = raw.slice(atIndex + 1) || null;
    }
  }

  return {
    valid: true,
    name: normalizeText(name),
    version: version ? normalizeText(version) : null
  };
}

export function isExactSemver(version) {
  return /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9a-z-.]+)?(?:\+[0-9a-z-.]+)?$/i.test(
    String(version ?? '')
  );
}

export function isDistTag(version) {
  return DIST_TAGS.has(normalizeText(version));
}

export function levenshtein(left, right) {
  const a = normalizeText(left);
  const b = normalizeText(right);
  if (a === b) {
    return 0;
  }
  if (!a.length) {
    return b.length;
  }
  if (!b.length) {
    return a.length;
  }

  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const substitutionCost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(
        previous[j] + 1,
        current[j - 1] + 1,
        previous[j - 1] + substitutionCost
      );
    }
    previous = current;
  }

  return previous[b.length];
}

export function pickNearest(target, corpus) {
  let nearest = null;
  let nearestDistance = Number.POSITIVE_INFINITY;

  for (const candidate of corpus) {
    const distance = levenshtein(target, candidate);
    if (distance < nearestDistance) {
      nearest = candidate;
      nearestDistance = distance;
    }
  }

  return { nearest, nearestDistance: Number.isFinite(nearestDistance) ? nearestDistance : null };
}

export function daysBetween(earlierIso, laterIso = new Date().toISOString()) {
  if (!earlierIso) {
    return null;
  }
  const earlier = new Date(earlierIso);
  const later = new Date(laterIso);
  if (Number.isNaN(earlier.getTime()) || Number.isNaN(later.getTime())) {
    return null;
  }
  return Math.max(0, (later.getTime() - earlier.getTime()) / (1000 * 60 * 60 * 24));
}

// True when an install script runs a file whose name looks machine-generated, e.g. `node c0nlywxa.cjs`
// or `node 31kbzord.cjs`. Legitimate install scripts use descriptive names (install.js, build.js).
// A name counts as random when it is 6-16 lowercase letters and digits with no separators, contains
// both, and either starts with a digit or switches between letters and digits at least twice.
// Names like es2015, sha256 or webpack5 (one switch, starts with a letter) are not flagged.
export function hasRandomScriptFilename(scriptValue) {
  const script = normalizeText(scriptValue);
  if (!script) {
    return false;
  }

  const files = [...script.matchAll(/(?:^|[\s;&|('"=])(?:\.{0,2}\/)?((?:[\w.-]+\/)*[\w.-]+)\.(?:c|m)?[jt]sx?\b/g)].map((match) => match[1]);
  return files.some((filePath) => {
    const base = filePath.split('/').pop();
    if (!/^[a-z0-9]{6,16}$/.test(base) || !/[a-z]/.test(base) || !/\d/.test(base)) {
      return false;
    }
    const switches = (base.match(/[a-z](?=\d)|\d(?=[a-z])/g) ?? []).length;
    return /^\d/.test(base) || switches >= 2;
  });
}

export function isSuspiciousScript(scriptValue) {
  const script = normalizeText(scriptValue);
  if (!script) {
    return false;
  }

  return [
    /\b(?:curl|wget)\b/,
    /\b(?:powershell|invoke-webrequest|iwr)\b/,
    /\b(?:ba)?sh\s+-c\b/,
    /\bchmod\s+\+x\b/,
    /\b(?:nc|netcat)\b/,
    /\bpython\s+-c\b/,
    /\bnode\s+-e\b/,
    /\bnode\s+(?:--[^\s]+\s+)*[^\s"']*\b(?:setup|install|preinstall|postinstall)\.js\b/,
    /\bbase64\s+-d\b/,
    /\beval\s*\(/,
    /\brequire\s*\(/,
    // direct node script execution in install hooks (e.g. node new.js, node <random>.cjs)
    /\bnode\s+(?:--[^\s]+\s+)*[^\s-][^\s]*\.(?:cjs|mjs|jsx?|tsx?)\b/,
    // sh/bash executing a script/path argument, including `sh <path>` / `bash <path>` (not -c/-s inline forms)
    /\b(?:ba)?sh\s+(?:-(?![cs]\b)[^\s]+\s+)*[^\s-][^\s]*/,
    // direct relative/absolute script execution (e.g. ./pre.sh)
    /(?:^|[;&|]\s*)\.{1,2}\/[^\s;&|]+/
  ].some((pattern) => pattern.test(script));
}

export function looksLikeBroadRange(range) {
  const value = normalizeText(range);
  if (!value) {
    return false;
  }

  return (
    value === '*' ||
    value === 'latest' ||
    value.includes('||') ||
    value.includes('x') ||
    value.includes('>=') ||
    value.includes('<=') ||
    value.startsWith('>') ||
    value.startsWith('<') ||
    value.startsWith('^') ||
    value.startsWith('~')
  );
}

export function fileTimeIso(value) {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

export function packageAgeRiskFromTimestamp(timestampIso) {
  const ageDays = daysBetween(timestampIso);
  if (ageDays === null) {
    return { value: 0, available: false };
  }
  return { value: 1 - Math.min(ageDays / PACKAGE_AGE_THRESHOLD_DAYS, 1), available: true };
}

export function versionAgeRiskFromTimestamp(timestampIso) {
  return packageAgeRiskFromTimestamp(timestampIso);
}