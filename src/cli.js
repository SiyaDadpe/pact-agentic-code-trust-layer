#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { analyzePackageRequest } from './orchestrator.js';
import { createDecisionLogger } from './logger.js';
import { buildSandboxCommand, runSandboxInstall } from './sandbox.js';
import {
  addAllowlistedPackage,
  createBypassDecision,
  isAllowlisted,
  readAllowlist,
  removeAllowlistedPackage
} from './allowlist.js';

function printUsage() {
  console.log([
    'Usage:',
    '  pact check <package[@version]> [package[@version] ...] [--json] [--log-file <path>]',
    '  pact npm install [npm install args...] [--json] [--log-file <path>] [--dry-run]',
    '  pact allow add <package-name>',
    '  pact allow remove <package-name>',
    '  pact allow list',
    '  pact sandbox shell',
    '  pact sandbox install <package[@version]> [package[@version] ...]',
    '',
    'Examples:',
    '  pact check react',
    '  pact check @scope/name@latest --json',
    '  pact npm install react express',
    '  pact npm install react --dry-run   # report the decision only, never spawns real npm install',
    '  pact sandbox shell',
    '  pact sandbox install react'
  ].join('\n'));
}

function parseArgs(argv) {
  const args = [...argv];
  const flags = { json: false, logFile: null, timeoutMs: 5000, dryRun: false };
  const positionals = [];

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === '--json') {
      flags.json = true;
      continue;
    }
    if (token === '--dry-run') {
      flags.dryRun = true;
      continue;
    }
    if (token === '--log-file') {
      flags.logFile = args[index + 1] ?? null;
      index += 1;
      continue;
    }
    if (token === '--timeout-ms') {
      flags.timeoutMs = Number(args[index + 1] ?? 5000);
      index += 1;
      continue;
    }
    positionals.push(token);
  }

  return { flags, positionals };
}

function isOption(token) {
  return String(token ?? '').startsWith('-');
}

function extractInstallSpecs(tokens) {
  const specs = [];
  for (const token of tokens) {
    if (!isOption(token)) {
      specs.push(token);
    }
  }
  return specs;
}

function readPackageJsonDependencies(cwd = process.cwd()) {
  const packageJsonPath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    return [];
  }

  try {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const groups = [packageJson.dependencies, packageJson.devDependencies, packageJson.optionalDependencies];
    return groups.flatMap((group) => Object.entries(group ?? {}).map(([name, version]) => `${name}@${version}`));
  } catch {
    return [];
  }
}

async function evaluateSpecs(specs, options = {}) {
  const logger = createDecisionLogger(options.logFile ?? undefined);
  const results = [];

  for (const spec of specs) {
    const result = isAllowlisted(spec, options.allowlistFile)
      ? createBypassDecision(spec, options.allowlistFile)
      : await analyzePackageRequest({ spec, ecosystem: 'npm' }, { timeoutMs: options.timeoutMs ?? 5000 });
    logger.write(result.logEntry ?? result.decision);
    results.push(result);
  }

  return results;
}

function aggregateAction(results) {
  const actions = results.map((result) => result.decision.decision);
  if (actions.includes('BLOCK')) {
    return 'BLOCK';
  }
  if (actions.includes('UNKNOWN')) {
    return 'UNKNOWN';
  }
  if (actions.includes('WARN')) {
    return 'WARN';
  }
  return 'ALLOW';
}

function printDecisions(results) {
  for (const decision of results.map((result) => result.decision)) {
    const confidence = decision.confidence === null ? 'n/a' : decision.confidence.toFixed(3);
    const risk = decision.risk_score === null ? 'n/a' : decision.risk_score.toFixed(3);
    console.log(`${decision.decision}: ${decision.requested_package.name}${decision.requested_package.version ? `@${decision.requested_package.version}` : ''}`);
    console.log(`  confidence=${confidence} risk=${risk}`);
    console.log(`  reason=${decision.reason}`);
  }
}

function resolveRealNpmBinary() {
  return process.env.PACT_REAL_NPM || 'npm';
}

function pinResolvedInstallArgs(npmArgs, results) {
  let resultIndex = 0;
  return npmArgs.map((token) => {
    if (isOption(token)) {
      return token;
    }

    const analysis = results[resultIndex];
    resultIndex += 1;
    const resolvedVersion = analysis?.registryResult?.resolvedVersion;
    const requestedVersion = analysis?.request?.version;
    if (!resolvedVersion || requestedVersion === resolvedVersion) {
      return token;
    }

    return `${analysis.request.full_name}@${resolvedVersion}`;
  });
}

async function runCheckCommand(argv) {
  const { flags, positionals } = parseArgs(argv);
  const specs = positionals.filter((token) => !token.startsWith('-'));
  if (!specs.length) {
    printUsage();
    process.exitCode = 1;
    return;
  }

  const results = await evaluateSpecs(specs, { logFile: flags.logFile, timeoutMs: flags.timeoutMs });
  const aggregate = aggregateAction(results);
  const output = {
    decision: aggregate,
    results: results.map((result) => result.decision)
  };

  if (flags.json) {
    console.log(JSON.stringify(output, null, 2));
  } else {
    printDecisions(results);
    console.log(`Aggregate: ${aggregate}`);
  }

  process.exitCode = aggregate === 'ALLOW' ? 0 : aggregate === 'WARN' ? 3 : aggregate === 'UNKNOWN' ? 4 : 2;
}

async function runNpmWrapper(argv) {
  const { flags, positionals } = parseArgs(argv);
  const npmCommand = positionals[0];
  if (!['install', 'i', 'ci'].includes(npmCommand)) {
    printUsage();
    process.exitCode = 1;
    return;
  }

  const npmArgs = positionals.slice(1);
  const installSpecs = extractInstallSpecs(npmArgs);
  const specs = installSpecs.length ? installSpecs : readPackageJsonDependencies();

  if (!specs.length) {
    if (flags.dryRun) {
      console.log(`[dry-run] no install specs found (nothing in args or package.json) - would run: npm ${npmCommand} ${npmArgs.join(' ')}`);
      process.exitCode = 0;
      return;
    }
    const result = spawnSync(resolveRealNpmBinary(), [npmCommand, ...npmArgs], { stdio: 'inherit' });
    process.exitCode = result.status ?? 0;
    return;
  }

  const results = await evaluateSpecs(specs, { logFile: flags.logFile, timeoutMs: flags.timeoutMs });
  const aggregate = aggregateAction(results);

  if (flags.json) {
    console.log(JSON.stringify({ decision: aggregate, results: results.map((result) => result.decision) }, null, 2));
  } else {
    printDecisions(results);
    console.log(`Aggregate: ${aggregate}`);
  }

  if (aggregate !== 'ALLOW') {
    process.exitCode = aggregate === 'WARN' ? 3 : aggregate === 'UNKNOWN' ? 4 : 2;
    return;
  }

  if (flags.dryRun) {
    const pinnedArgs = pinResolvedInstallArgs(npmArgs, results);
    if (!flags.json) {
      console.log(`[dry-run] ALLOW - would run: npm ${npmCommand} ${pinnedArgs.join(' ')}`);
    }
    process.exitCode = 0;
    return;
  }

  const pinnedArgs = pinResolvedInstallArgs(npmArgs, results);
  const result = spawnSync(resolveRealNpmBinary(), [npmCommand, ...pinnedArgs], { stdio: 'inherit' });
  process.exitCode = result.status ?? 0;
}

function runAllowCommand(argv) {
  const [subcommand, packageSpec] = argv;

  if (subcommand === 'add' && packageSpec) {
    const result = addAllowlistedPackage(packageSpec);
    console.log(`Allowlisted ${result.packageName}`);
    console.log(`Allowlist: ${result.filePath}`);
    return;
  }

  if (subcommand === 'remove' && packageSpec) {
    const result = removeAllowlistedPackage(packageSpec);
    console.log(`Removed ${result.packageName}`);
    console.log(`Allowlist: ${result.filePath}`);
    return;
  }

  if (subcommand === 'list') {
    const packages = readAllowlist();
    console.log(packages.length ? packages.join('\n') : '(allowlist is empty)');
    return;
  }

  printUsage();
  process.exitCode = 1;
}

async function runSandboxCommand(argv) {
  const [subcommand, ...rest] = argv;

  if (subcommand === 'shell') {
    const sandbox = buildSandboxCommand();
    const result = spawnSync('docker', sandbox.args, {
      stdio: 'inherit',
      env: process.env
    });
    process.exitCode = result.status ?? 0;
    return;
  }

  if (subcommand === 'install') {
    const specs = rest.filter((token) => !token.startsWith('-'));
    const result = await runSandboxInstall(specs);
    process.exitCode = result.ok ? 0 : 1;
    return;
  }

  printUsage();
  process.exitCode = 1;
}

async function main() {
  const argv = process.argv.slice(2);
  const [command, ...rest] = argv;

  if (!command || command === '--help' || command === '-h') {
    printUsage();
    return;
  }

  if (command === 'check') {
    await runCheckCommand(rest);
    return;
  }

  if (command === 'npm') {
    await runNpmWrapper(rest);
    return;
  }

  if (command === 'sandbox') {
    await runSandboxCommand(rest);
    return;
  }

  if (command === 'allow') {
    runAllowCommand(rest);
    return;
  }

  printUsage();
  process.exitCode = 1;
}

main().catch((error) => {
  console.error(error?.stack ?? String(error));
  process.exitCode = 1;
});