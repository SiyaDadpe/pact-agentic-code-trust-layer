#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ANALYSIS_DIR = path.resolve(SCRIPT_DIR, '..');
const DATA_DIR = path.join(ANALYSIS_DIR, 'data');
const OUTPUT_DIR = path.join(ANALYSIS_DIR, 'output');
const REPO_ROOT = path.resolve(ANALYSIS_DIR, '..', '..');

const args = process.argv.slice(2);
function argValue(name, fallback) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
}

const csvPath = path.resolve(argValue('--csv', path.join(os.homedir(), 'Desktop', 'npmanalysis_cases.csv')));
const writeRebuilt = args.includes('--write-rebuilt');
const rebuiltPath = path.resolve(argValue('--rebuilt-out', path.join(OUTPUT_DIR, 'npmanalysis_cases.rebuilt.csv')));

const { parsePackageSpec } = await import(pathToFileURL(path.join(REPO_ROOT, 'src', 'utils.js')).href);

const FOLDERS = [
  { folder: 'zip_benign', label: 'benign', fileName: 'zip-benign-tree.json' },
  { folder: 'zip_malware', label: 'malicious', fileName: 'zip-malware-tree.json' }
];

function readCsv(filePath) {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const text = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
  const lines = text.split(/\r?\n/).filter((line) => line.length > 0);
  const header = lines.shift()?.split(',') ?? [];
  const rows = lines.map((line, index) => {
    const values = line.split(',');
    return {
      line: index + 2,
      package_name: values[0],
      package_version: values[1],
      label: values[2],
      source_path: values[3],
      archive_size_bytes: values[4]
    };
  });
  return { header, rows };
}

function csvEscape(value) {
  const text = String(value ?? '');
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function toCsv(rows, header) {
  return `${header.join(',')}\n${rows.map((row) => header.map((key) => csvEscape(row[key])).join(',')).join('\n')}\n`;
}

function parseRecord(folder, label, entry) {
  const segments = entry.path.split('/');
  const issues = [];
  if (segments.length !== 3) {
    issues.push(`expected 3 path segments, got ${segments.length}`);
  }
  if (!entry.path.endsWith('.tgz')) {
    issues.push('blob does not end in .tgz');
  }
  const [packageDir = '', version = '', fileName = ''] = segments;
  const packageName = packageDir.replaceAll('##', '/');
  if (!packageDir) {
    issues.push('empty package directory');
  }
  if (!version) {
    issues.push('empty version directory');
  }
  if (packageName.includes('##')) {
    issues.push('unconverted ## in package name');
  }
  if (packageName.startsWith('@')) {
    const parts = packageName.split('/');
    if (parts.length !== 2 || parts.some((part) => !part)) {
      issues.push('invalid scoped package name');
    }
  } else if (packageName.includes('/') || packageName.includes('@')) {
    issues.push('invalid unscoped package name');
  }
  if (/[\s,]/.test(packageName) || /[\s,]/.test(version)) {
    issues.push('package name or version contains whitespace/comma');
  }

  return {
    package_name: packageName,
    package_version: version,
    label,
    source_path: `Dataset/${folder}/${entry.path}`,
    archive_size_bytes: String(entry.size ?? ''),
    package_dir: packageDir,
    file_name: fileName,
    path: entry.path,
    issues
  };
}

function summarizeValues(values) {
  return values.reduce((summary, value) => {
    summary[value] = (summary[value] ?? 0) + 1;
    return summary;
  }, {});
}

function compareWithCurrentCsv(records, currentCsv) {
  const currentBySource = new Map(currentCsv.rows.map((row) => [row.source_path, row]));
  const canonicalBySource = new Map(records.map((record) => [record.source_path, record]));
  const missing = records.filter((record) => !currentBySource.has(record.source_path));
  const extra = currentCsv.rows.filter((row) => !canonicalBySource.has(row.source_path));
  const mismatches = { package_name: [], package_version: [], label: [], archive_size_bytes: [] };

  for (const record of records) {
    const current = currentBySource.get(record.source_path);
    if (!current) {
      continue;
    }
    for (const key of Object.keys(mismatches)) {
      if (String(current[key]) !== String(record[key])) {
        mismatches[key].push({
          source_path: record.source_path,
          current: current[key],
          canonical: record[key]
        });
      }
    }
  }

  return { currentBySource, canonicalBySource, missing, extra, mismatches };
}

function caseClassification(packageName, version, parsed) {
  const nameLower = packageName.toLowerCase();
  const versionLower = version.toLowerCase();
  const nameCaseOnly = parsed.name === nameLower && parsed.name !== packageName;
  const versionCaseOnly = parsed.version === versionLower && parsed.version !== version;
  const exact = parsed.name === packageName && parsed.version === version;
  const structural = !parsed.valid
    || (parsed.name !== packageName && !nameCaseOnly)
    || (parsed.version !== version && !versionCaseOnly);
  return { exact, nameCaseOnly, versionCaseOnly, structural };
}

function main() {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const treeMetadata = {};
  const records = [];
  const structureIssues = [];
  const noncanonicalFileNames = [];

  for (const folder of FOLDERS) {
    const treePath = path.join(DATA_DIR, folder.fileName);
    const tree = JSON.parse(fs.readFileSync(treePath, 'utf8'));
    const blobs = (tree.tree ?? []).filter((entry) => entry.type === 'blob');
    treeMetadata[folder.folder] = {
      sha: tree.sha,
      truncated: Boolean(tree.truncated),
      truncation_fallback: Boolean(tree.truncation_fallback),
      entries: (tree.tree ?? []).length,
      blobs: blobs.length,
      fetched_at: tree.fetched_at ?? null
    };

    for (const blob of blobs) {
      const record = parseRecord(folder.folder, folder.label, blob);
      if (record.issues.length > 0) {
        structureIssues.push({
          source_path: record.source_path,
          path: blob.path,
          issues: record.issues
        });
      }
      if (blob.path.split('/')[2] !== `${record.package_dir}-${record.package_version}.tgz`) {
        noncanonicalFileNames.push({
          source_path: record.source_path,
          file_name: record.file_name,
          expected_by_folder_convention: `${record.package_dir}-${record.package_version}.tgz`
        });
      }
      records.push(record);
    }
  }

  const sourceCounts = summarizeValues(records.map((record) => record.source_path));
  const duplicateSources = Object.entries(sourceCounts).filter(([, count]) => count > 1);
  const nameVersionCounts = summarizeValues(records.map((record) => `${record.package_name}@${record.package_version}`));
  const duplicateNameVersions = Object.entries(nameVersionCounts).filter(([, count]) => count > 1);

  const scopedRecords = records.filter((record) => record.package_name.startsWith('@'));
  const parseValidation = {
    exact: [],
    caseOnly: [],
    structuralFailures: []
  };
  for (const record of records) {
    const spec = `${record.package_name}@${record.package_version}`;
    const parsed = parsePackageSpec(spec);
    const classification = caseClassification(record.package_name, record.package_version, parsed);
    const entry = {
      label: record.label,
      source_path: record.source_path,
      spec,
      parsed_name: parsed.name,
      parsed_version: parsed.version
    };
    if (classification.structural) {
      parseValidation.structuralFailures.push(entry);
    } else if (classification.exact) {
      parseValidation.exact.push(entry);
    } else {
      parseValidation.caseOnly.push(entry);
    }
  }

  const scopedValidation = {
    total: scopedRecords.length,
    benign: scopedRecords.filter((record) => record.label === 'benign').length,
    malicious: scopedRecords.filter((record) => record.label === 'malicious').length,
    structural_failures: parseValidation.structuralFailures.filter((entry) => entry.spec.startsWith('@')).length,
    case_only_differences: parseValidation.caseOnly.filter((entry) => entry.spec.startsWith('@')).length
  };

  const recordsByLabel = summarizeValues(records.map((record) => record.label));
  const packageNamesByLabel = {
    benign: new Set(records.filter((record) => record.label === 'benign').map((record) => record.package_name)).size,
    malicious: new Set(records.filter((record) => record.label === 'malicious').map((record) => record.package_name)).size
  };

  const currentCsv = readCsv(csvPath);
  const comparison = currentCsv ? compareWithCurrentCsv(records, currentCsv) : null;

  const missingByLabel = comparison ? summarizeValues(comparison.missing.map((record) => record.label)) : null;
  const missingPackageNames = comparison
    ? new Set(comparison.missing.map((record) => record.package_name)).size
    : null;

  const rebuildBlockers = [];
  if (!currentCsv) {
    rebuildBlockers.push(`current CSV not found: ${csvPath}`);
  }
  if (structureIssues.length > 0) {
    rebuildBlockers.push(`${structureIssues.length} records have path/structure issues`);
  }
  if (duplicateSources.length > 0) {
    rebuildBlockers.push(`${duplicateSources.length} duplicate source paths`);
  }
  if (duplicateNameVersions.length > 0) {
    rebuildBlockers.push(`${duplicateNameVersions.length} duplicate package@version records`);
  }
  if (comparison) {
    if (comparison.extra.length > 0) {
      rebuildBlockers.push(`${comparison.extra.length} CSV rows are not present in the GitHub trees`);
    }
    for (const [key, values] of Object.entries(comparison.mismatches)) {
      if (values.length > 0) {
        rebuildBlockers.push(`${values.length} ${key} mismatches on overlapping rows`);
      }
    }
  }

  const rebuildAllowed = rebuildBlockers.length === 0;
  let rebuilt = null;
  if (writeRebuilt && rebuildAllowed) {
    fs.mkdirSync(path.dirname(rebuiltPath), { recursive: true });
    const header = ['package_name', 'package_version', 'label', 'source_path', 'archive_size_bytes'];
    fs.writeFileSync(rebuiltPath, toCsv(records, header));
    rebuilt = {
      path: rebuiltPath,
      rows: records.length,
      by_label: recordsByLabel
    };
  }

  const verification = {
    generated_at: new Date().toISOString(),
    source_repo: 'lxyeternal/NPMAnalysis',
    source_ref: 'main',
    folder_trees: treeMetadata,
    counts: {
      total: records.length,
      by_label: recordsByLabel,
      unique_package_names: {
        total: new Set(records.map((record) => record.package_name)).size,
        ...packageNamesByLabel
      },
      scoped: scopedValidation
    },
    structure: {
      issues: structureIssues,
      noncanonical_file_names: noncanonicalFileNames.length,
      noncanonical_file_name_samples: noncanonicalFileNames.slice(0, 20),
      duplicate_source_paths: duplicateSources,
      duplicate_name_versions: duplicateNameVersions
    },
    package_spec_validation: {
      exact: parseValidation.exact.length,
      case_only_differences: parseValidation.caseOnly.length,
      structural_failures: parseValidation.structuralFailures.length,
      case_only_samples: parseValidation.caseOnly.slice(0, 50),
      structural_failure_samples: parseValidation.structuralFailures.slice(0, 20)
    },
    current_csv: currentCsv ? {
      path: csvPath,
      rows: currentCsv.rows.length,
      by_label: summarizeValues(currentCsv.rows.map((row) => row.label)),
      missing_from_csv: comparison.missing.length,
      missing_by_label: missingByLabel,
      missing_unique_package_names: missingPackageNames,
      extra_rows: comparison.extra.length,
      overlapping_row_mismatches: Object.fromEntries(
        Object.entries(comparison.mismatches).map(([key, values]) => [key, {
          count: values.length,
          samples: values.slice(0, 20)
        }])
      )
    } : null,
    rebuild: {
      allowed: rebuildAllowed,
      blockers: rebuildBlockers,
      output: rebuilt
    }
  };

  fs.writeFileSync(path.join(OUTPUT_DIR, 'verification.json'), `${JSON.stringify(verification, null, 2)}\n`);

  if (comparison) {
    const missingHeader = ['package_name', 'package_version', 'label', 'source_path', 'archive_size_bytes'];
    fs.writeFileSync(path.join(OUTPUT_DIR, 'missing_from_current_csv.csv'), toCsv(comparison.missing, missingHeader));
  }

  const report = buildReport(verification);
  fs.writeFileSync(path.join(OUTPUT_DIR, 'verification_report.md'), report);

  console.log(report);
  if (writeRebuilt && !rebuildAllowed) {
    process.exitCode = 1;
  }
}

function buildReport(verification) {
  const lines = [];
  const current = verification.current_csv;
  lines.push('# NPMAnalysis dataset verification');
  lines.push('');
  lines.push(`Generated: ${verification.generated_at}`);
  lines.push('');
  lines.push('## Folder tree counts');
  lines.push('');
  lines.push('| Folder | Tree SHA | Truncated | Blobs (.tgz) | Entries |');
  lines.push('| --- | --- | --- | ---: | ---: |');
  for (const [folder, metadata] of Object.entries(verification.folder_trees)) {
    lines.push(`| ${folder} | ${metadata.sha} | ${metadata.truncated} | ${metadata.blobs} | ${metadata.entries} |`);
  }
  lines.push('');
  lines.push('## Canonical record counts');
  lines.push('');
  lines.push(`Total: **${verification.counts.total}** (benign **${verification.counts.by_label.benign ?? 0}**, malicious **${verification.counts.by_label.malicious ?? 0}**)`);
  lines.push('');
  lines.push(`Unique package names: **${verification.counts.unique_package_names.total}** (benign **${verification.counts.unique_package_names.benign}**, malicious **${verification.counts.unique_package_names.malicious}**)`);
  lines.push('');
  lines.push(`Scoped records: **${verification.counts.scoped.total}** (benign **${verification.counts.scoped.benign}**, malicious **${verification.counts.scoped.malicious}**); structural parse failures **${verification.counts.scoped.structural_failures}**, case-only normalizations **${verification.counts.scoped.case_only_differences}**.`);
  lines.push('');
  if (current) {
    lines.push('## Comparison with current CSV');
    lines.push('');
    lines.push(`Current CSV: \`${current.path}\``);
    lines.push('');
    lines.push(`Rows: **${current.rows}** (benign **${current.by_label.benign ?? 0}**, malicious **${current.by_label.malicious ?? 0}**).`);
    lines.push('');
    lines.push(`Missing from current CSV: **${current.missing_from_csv}** (benign **${current.missing_by_label.benign ?? 0}**, malicious **${current.missing_by_label.malicious ?? 0}**), covering **${current.missing_unique_package_names}** unique package names.`);
    lines.push('');
    lines.push(`Extra CSV rows not found in the GitHub trees: **${current.extra_rows}**.`);
    lines.push('');
    const mismatchCounts = Object.fromEntries(
      Object.entries(current.overlapping_row_mismatches).map(([key, value]) => [key, value.count])
    );
    lines.push(`Overlapping-row mismatches: package_name **${mismatchCounts.package_name}**, package_version **${mismatchCounts.package_version}**, label **${mismatchCounts.label}**, archive_size_bytes **${mismatchCounts.archive_size_bytes}**.`);
    lines.push('');
  }
  lines.push('## Extraction validation');
  lines.push('');
  lines.push(`Path/structure issues: **${verification.structure.issues.length}**`);
  lines.push('');
  lines.push(`Duplicate source paths: **${verification.structure.duplicate_source_paths.length}**; duplicate package@version records: **${verification.structure.duplicate_name_versions.length}**.`);
  lines.push('');
  lines.push(`Noncanonical archive file names: **${verification.structure.noncanonical_file_names}** (parsed from folder path, not filename).`);
  lines.push('');
  lines.push(`Spec round-trip exact: **${verification.package_spec_validation.exact}**; case-only differences: **${verification.package_spec_validation.case_only_differences}**; structural failures: **${verification.package_spec_validation.structural_failures}**.`);
  lines.push('');
  lines.push('## Rebuild');
  lines.push('');
  lines.push(`Allowed: **${verification.rebuild.allowed}**`);
  if (verification.rebuild.blockers.length > 0) {
    lines.push('');
    lines.push('Blockers:');
    for (const blocker of verification.rebuild.blockers) {
      lines.push(`- ${blocker}`);
    }
  }
  if (verification.rebuild.output) {
    lines.push('');
    lines.push(`Rebuilt CSV: \`${verification.rebuild.output.path}\` with **${verification.rebuild.output.rows}** rows.`);
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

main();
