#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { analyzePackageRequest } from '../../../src/orchestrator.js';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ANALYSIS_DIR = path.resolve(SCRIPT_DIR, '..');
const OUTPUT_DIR = path.join(ANALYSIS_DIR, 'output');
const REPO_ROOT = path.resolve(ANALYSIS_DIR, '..', '..');

const args = process.argv.slice(2);
function argValue(name, fallback) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
}
function hasFlag(name) {
  return args.includes(name);
}

const csvPath = path.resolve(argValue('--csv', path.join(OUTPUT_DIR, 'npmanalysis_cases.rebuilt.csv')));
const resultsPath = path.resolve(argValue('--results', path.join(OUTPUT_DIR, 'check-results.jsonl')));
const metricsJsonPath = path.resolve(argValue('--metrics-json', path.join(OUTPUT_DIR, 'metrics.json')));
const metricsMdPath = path.resolve(argValue('--metrics-md', path.join(OUTPUT_DIR, 'metrics.md')));
const concurrency = Math.max(1, Number(argValue('--concurrency', '8')));
const timeoutMs = Math.max(1000, Number(argValue('--timeout-ms', '10000')));
const limit = Math.max(0, Number(argValue('--limit', '0')));
const metricsOnly = hasFlag('--metrics-only');
const fresh = hasFlag('--fresh');
const mode = argValue('--mode', 'module');
const batchSize = Math.max(1, Number(argValue('--batch-size', '25')));
const cliPath = path.resolve(argValue('--cli', path.join(REPO_ROOT, 'src', 'cli.js')));
const positiveDecisions = argValue('--positive-decisions', 'BLOCK').split(',').map((value) => value.trim()).filter(Boolean);
const warnPositiveDecisions = argValue('--warn-positive-decisions', 'BLOCK,WARN').split(',').map((value) => value.trim()).filter(Boolean);

function parseCsv(filePath) {
  const lines = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/).filter((line) => line.length > 0);
  const header = lines.shift().split(',');
  const required = ['package_name', 'package_version', 'label', 'source_path'];
  for (const key of required) {
    if (!header.includes(key)) {
      throw new Error(`CSV missing required column: ${key}`);
    }
  }
  return lines.map((line) => {
    const values = line.split(',');
    return Object.fromEntries(header.map((key, index) => [key, values[index]]));
  });
}

function readResults(filePath) {
  if (!fs.existsSync(filePath)) {
    return [];
  }
  const rows = [];
  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    if (!line.trim()) {
      continue;
    }
    try {
      rows.push(JSON.parse(line));
    } catch {
      continue;
    }
  }
  return rows;
}

function decisionCounts(rows) {
  const counts = { ALLOW: 0, WARN: 0, BLOCK: 0, UNKNOWN: 0 };
  for (const row of rows) {
    counts[row.decision] = (counts[row.decision] ?? 0) + 1;
  }
  return counts;
}

function computeMetrics(rows, positiveSet) {
  const positive = new Set(positiveSet);
  const total = rows.length;
  const byLabel = {
    benign: rows.filter((row) => row.label === 'benign'),
    malicious: rows.filter((row) => row.label === 'malicious')
  };

  function countsFor(labelRows) {
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    for (const row of labelRows) {
      const predictedPositive = positive.has(row.decision);
      if (row.label === 'malicious') {
        if (predictedPositive) {
          tp += 1;
        } else {
          fn += 1;
        }
      } else if (predictedPositive) {
        fp += 1;
      } else {
        tn += 1;
      }
    }
    return { tp, fp, tn, fn };
  }

  function metricsFromCounts(counts) {
    const { tp, fp, tn, fn } = counts;
    const predictedPositive = tp + fp;
    const actualPositive = tp + fn;
    const actualNegative = tn + fp;
    const predictedNegative = tn + fn;
    const totalCount = tp + fp + tn + fn;
    const precision = predictedPositive === 0 ? null : tp / predictedPositive;
    const recall = actualPositive === 0 ? null : tp / actualPositive;
    const specificity = actualNegative === 0 ? null : tn / actualNegative;
    const npv = predictedNegative === 0 ? null : tn / predictedNegative;
    const accuracy = totalCount === 0 ? null : (tp + tn) / totalCount;
    const f1 = precision === null || recall === null || precision + recall === 0
      ? null
      : (2 * precision * recall) / (precision + recall);
    const balancedAccuracy = recall === null || specificity === null ? null : (recall + specificity) / 2;
    const falsePositiveRate = actualNegative === 0 ? null : fp / actualNegative;
    const falseNegativeRate = actualPositive === 0 ? null : fn / actualPositive;
    const denominator = Math.sqrt(
      (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    );
    const mcc = denominator === 0
      ? null
      : ((tp * tn) - (fp * fn)) / denominator;

    return {
      tp,
      fp,
      tn,
      fn,
      total: totalCount,
      precision,
      recall,
      specificity,
      npv,
      accuracy,
      f1,
      balanced_accuracy: balancedAccuracy,
      false_positive_rate: falsePositiveRate,
      false_negative_rate: falseNegativeRate,
      mcc
    };
  }

  const all = metricsFromCounts(countsFor(rows));
  const coveredRows = rows.filter((row) => row.decision !== 'UNKNOWN');
  const covered = metricsFromCounts(countsFor(coveredRows));

  return {
    positive_decisions: [...positive],
    all_cases: all,
    covered_cases: {
      ...covered,
      coverage: total === 0 ? null : coveredRows.length / total,
      unknown_excluded: total - coveredRows.length
    },
    by_label: {
      benign: {
        total: byLabel.benign.length,
        decisions: decisionCounts(byLabel.benign)
      },
      malicious: {
        total: byLabel.malicious.length,
        decisions: decisionCounts(byLabel.malicious)
      }
    }
  };
}

function pct(value) {
  return value === null || value === undefined ? 'n/a' : `${(value * 100).toFixed(2)}%`;
}
function num(value) {
  return value === null || value === undefined ? 'n/a' : value.toFixed(4);
}

function buildMarkdown(metrics) {
  const primary = metrics.primary;
  const alternate = metrics.warn_positive;
  const lines = [];
  lines.push('# PACT check accuracy on NPMAnalysis');
  lines.push('');
  lines.push(`Cases: **${metrics.cases}** (benign **${metrics.case_labels.benign ?? 0}**, malicious **${metrics.case_labels.malicious ?? 0}**)`);
  lines.push('');
  lines.push('## Primary metrics');
  lines.push('');
  lines.push(`Positive decisions: **${primary.positive_decisions.join(', ')}**`);
  lines.push('');
  lines.push('| Metric | All cases | Covered cases (UNKNOWN excluded) |');
  lines.push('| --- | ---: | ---: |');
  lines.push(`| Accuracy | ${pct(primary.all_cases.accuracy)} | ${pct(primary.covered_cases.accuracy)} |`);
  lines.push(`| Precision | ${pct(primary.all_cases.precision)} | ${pct(primary.covered_cases.precision)} |`);
  lines.push(`| Recall | ${pct(primary.all_cases.recall)} | ${pct(primary.covered_cases.recall)} |`);
  lines.push(`| Specificity | ${pct(primary.all_cases.specificity)} | ${pct(primary.covered_cases.specificity)} |`);
  lines.push(`| F1 | ${num(primary.all_cases.f1)} | ${num(primary.covered_cases.f1)} |`);
  lines.push(`| Balanced accuracy | ${pct(primary.all_cases.balanced_accuracy)} | ${pct(primary.covered_cases.balanced_accuracy)} |`);
  lines.push(`| MCC | ${num(primary.all_cases.mcc)} | ${num(primary.covered_cases.mcc)} |`);
  lines.push(`| NPV | ${pct(primary.all_cases.npv)} | ${pct(primary.covered_cases.npv)} |`);
  lines.push(`| False positive rate | ${pct(primary.all_cases.false_positive_rate)} | ${pct(primary.covered_cases.false_positive_rate)} |`);
  lines.push(`| False negative rate | ${pct(primary.all_cases.false_negative_rate)} | ${pct(primary.covered_cases.false_negative_rate)} |`);
  lines.push('');
  lines.push(`Coverage: **${pct(primary.covered_cases.coverage)}**; UNKNOWN excluded: **${primary.covered_cases.unknown_excluded}**`);
  lines.push('');
  lines.push('### Confusion matrix');
  lines.push('');
  lines.push('| Actual | Predicted positive | Predicted negative |');
  lines.push('| --- | ---: | ---: |');
  lines.push(`| Malicious | ${primary.all_cases.tp} (TP) | ${primary.all_cases.fn} (FN) |`);
  lines.push(`| Benign | ${primary.all_cases.fp} (FP) | ${primary.all_cases.tn} (TN) |`);
  lines.push('');
  lines.push('## WARN treated as positive');
  lines.push('');
  lines.push(`Positive decisions: **${alternate.positive_decisions.join(', ')}**`);
  lines.push('');
  lines.push('| Metric | All cases | Covered cases (UNKNOWN excluded) |');
  lines.push('| --- | ---: | ---: |');
  lines.push(`| Accuracy | ${pct(alternate.all_cases.accuracy)} | ${pct(alternate.covered_cases.accuracy)} |`);
  lines.push(`| Precision | ${pct(alternate.all_cases.precision)} | ${pct(alternate.covered_cases.precision)} |`);
  lines.push(`| Recall | ${pct(alternate.all_cases.recall)} | ${pct(alternate.covered_cases.recall)} |`);
  lines.push(`| Specificity | ${pct(alternate.all_cases.specificity)} | ${pct(alternate.covered_cases.specificity)} |`);
  lines.push(`| F1 | ${num(alternate.all_cases.f1)} | ${num(alternate.covered_cases.f1)} |`);
  lines.push(`| Balanced accuracy | ${pct(alternate.all_cases.balanced_accuracy)} | ${pct(alternate.covered_cases.balanced_accuracy)} |`);
  lines.push(`| MCC | ${num(alternate.all_cases.mcc)} | ${num(alternate.covered_cases.mcc)} |`);
  lines.push('');
  lines.push('## Decision distribution');
  lines.push('');
  lines.push('| Label | ALLOW | WARN | BLOCK | UNKNOWN | Total |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
  for (const label of ['benign', 'malicious']) {
    const entry = primary.by_label[label];
    lines.push(`| ${label} | ${entry.decisions.ALLOW ?? 0} | ${entry.decisions.WARN ?? 0} | ${entry.decisions.BLOCK ?? 0} | ${entry.decisions.UNKNOWN ?? 0} | ${entry.total} |`);
  }
  lines.push(`| overall | ${metrics.overall_decisions.ALLOW ?? 0} | ${metrics.overall_decisions.WARN ?? 0} | ${metrics.overall_decisions.BLOCK ?? 0} | ${metrics.overall_decisions.UNKNOWN ?? 0} | ${metrics.cases} |`);
  lines.push('');
  return `${lines.join('\n')}\n`;
}

function rowSpec(row) {
  return `${row.package_name}@${row.package_version}`;
}

function moduleOutput(row, result, error) {
  return {
    package_name: row.package_name,
    package_version: row.package_version,
    label: row.label,
    source_path: row.source_path,
    spec: rowSpec(row),
    normalized_name: result?.request?.full_name ?? null,
    normalized_version: result?.request?.version ?? null,
    decision: result?.decision?.decision ?? 'UNKNOWN',
    risk_score: result?.decision?.risk_score ?? null,
    confidence: result?.decision?.confidence ?? null,
    existence_status: result?.existenceCheck?.status ?? result?.decision?.existence_check?.status ?? null,
    osv_malicious: result?.osvResult?.malicious ?? null,
    osv_unavailable: result?.osvResult?.unavailable ?? null,
    reason: result?.decision?.reason ?? error,
    error
  };
}

function cliOutput(row, result, error) {
  return {
    package_name: row.package_name,
    package_version: row.package_version,
    label: row.label,
    source_path: row.source_path,
    spec: rowSpec(row),
    normalized_name: result?.requested_package?.name ?? null,
    normalized_version: result?.requested_package?.version ?? null,
    decision: result?.decision ?? 'UNKNOWN',
    risk_score: result?.risk_score ?? null,
    confidence: result?.confidence ?? null,
    existence_status: result?.existence_check?.status ?? null,
    osv_malicious: result?.osv_result?.malicious ?? null,
    osv_unavailable: result?.osv_result?.unavailable ?? null,
    reason: result?.reason ?? error,
    error
  };
}

function runCliBatch(batch) {
  const specs = batch.map(rowSpec);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, 'check', ...specs, '--json', '--timeout-ms', String(timeoutMs)], {
      cwd: REPO_ROOT,
      env: process.env
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      try {
        const parsed = JSON.parse(stdout);
        if (!Array.isArray(parsed.results) || parsed.results.length !== batch.length) {
          throw new Error(`unexpected result count ${parsed.results?.length} for ${batch.length} specs`);
        }
        resolve(parsed.results);
      } catch (error) {
        reject(new Error(`CLI exit ${code}: ${error.message}${stderr ? `; stderr: ${stderr.slice(0, 500)}` : ''}${stdout ? `; stdout: ${stdout.slice(0, 500)}` : ''}`));
      }
    });
  });
}

async function runCliBatchWithRetry(batch) {
  let lastError = null;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const results = await runCliBatch(batch);
      return batch.map((row, index) => cliOutput(row, results[index], null));
    } catch (error) {
      lastError = error;
    }
  }
  return batch.map((row) => cliOutput(row, null, String(lastError?.message ?? lastError)));
}

async function runCases(pending) {
  fs.mkdirSync(path.dirname(resultsPath), { recursive: true });
  let completed = 0;

  if (mode === 'cli') {
    const batches = [];
    for (let index = 0; index < pending.length; index += batchSize) {
      batches.push(pending.slice(index, index + batchSize));
    }
    let nextBatch = 0;

    async function worker() {
      while (true) {
        const index = nextBatch;
        nextBatch += 1;
        if (index >= batches.length) {
          return;
        }
        const outputs = await runCliBatchWithRetry(batches[index]);
        fs.appendFileSync(resultsPath, outputs.map((output) => `${JSON.stringify(output)}\n`).join(''));
        completed += outputs.length;
        if (completed % 100 === 0 || completed === pending.length) {
          console.error(`checked ${completed}/${pending.length}`);
        }
      }
    }

    await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, batches.length)) }, () => worker()));
    return;
  }

  let nextIndex = 0;

  async function worker() {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= pending.length) {
        return;
      }
      const row = pending[index];
      let result;
      let error = null;
      try {
        result = await analyzePackageRequest({ spec: rowSpec(row), ecosystem: 'npm' }, { timeoutMs });
      } catch (caught) {
        error = String(caught?.message ?? caught);
      }

      fs.appendFileSync(resultsPath, `${JSON.stringify(moduleOutput(row, result, error))}\n`);
      completed += 1;
      if (completed % 100 === 0 || completed === pending.length) {
        console.error(`checked ${completed}/${pending.length}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, pending.length)) }, () => worker()));
}

async function main() {
  const cases = parseCsv(csvPath);
  const limitedCases = limit > 0 ? cases.slice(0, limit) : cases;
  const existing = fresh ? [] : readResults(resultsPath);
  const existingBySource = new Map(existing.map((row) => [row.source_path, row]));
  const retryUnknown = hasFlag('--retry-unknown');
  const pending = limitedCases.filter((row) => {
    const previous = existingBySource.get(row.source_path);
    return !previous || (retryUnknown && previous.decision === 'UNKNOWN');
  });

  console.log(`mode=${mode} cases=${limitedCases.length} existing_results=${existing.length} pending=${pending.length}`);

  if (!metricsOnly && pending.length > 0) {
    await runCases(pending);
  }

  const allResults = readResults(resultsPath);
  const resultBySource = new Map(allResults.map((row) => [row.source_path, row]));
  const joined = limitedCases
    .map((row) => resultBySource.get(row.source_path))
    .filter(Boolean);

  const overallDecisions = decisionCounts(joined);
  const metrics = {
    generated_at: new Date().toISOString(),
    csv: csvPath,
    results: resultsPath,
    cases: joined.length,
    case_labels: {
      benign: joined.filter((row) => row.label === 'benign').length,
      malicious: joined.filter((row) => row.label === 'malicious').length
    },
    overall_decisions: overallDecisions,
    primary: computeMetrics(joined, positiveDecisions),
    warn_positive: computeMetrics(joined, warnPositiveDecisions)
  };

  fs.mkdirSync(path.dirname(metricsJsonPath), { recursive: true });
  fs.writeFileSync(metricsJsonPath, `${JSON.stringify(metrics, null, 2)}\n`);
  fs.writeFileSync(metricsMdPath, buildMarkdown(metrics));
  console.log(`wrote ${metricsJsonPath}`);
  console.log(`wrote ${metricsMdPath}`);
}

main().catch((error) => {
  console.error(error.stack ?? error.message);
  process.exitCode = 1;
});
