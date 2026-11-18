import { spawnSync } from 'node:child_process';
import { analyzePackageRequest } from './orchestrator.js';

export async function evaluateInstallSpec(spec, options = {}) {
  const analysis = await analyzePackageRequest({ spec, ecosystem: 'npm' }, { timeoutMs: options.timeoutMs ?? 5000 });
  const decision = analysis.decision ?? analysis.logEntry ?? { decision: 'ALLOW', reason: 'no_decision', risk_score: 0, confidence: 0 };

  return {
    input: spec,
    action: decision.decision ?? decision.action ?? 'ALLOW',
    decision: decision.decision ?? decision.action ?? 'ALLOW',
    risk_score: decision.risk_score ?? 0,
    confidence: decision.confidence ?? 0,
    reason: decision.reason ?? 'no_reason',
    details: analysis
  };
}

export function dockerAvailable() {
  const result = spawnSync('docker', ['info'], {
    stdio: 'pipe',
    encoding: 'utf8'
  });

  return result.status === 0;
}

export async function runSandboxInstall(specs, options = {}) {
  const installSpecs = (specs ?? []).filter(Boolean);

  if (!installSpecs.length) {
    return { ok: true, mode: 'no-install', evaluated: [], executed: false };
  }

  if (!dockerAvailable()) {
    return {
      ok: false,
      mode: 'docker-unavailable',
      evaluated: [],
      executed: false,
      message: 'Docker daemon is not running. Start Docker Desktop or the Docker engine before enabling sandbox mode.'
    };
  }

  const evaluated = [];
  for (const spec of installSpecs) {
    const result = await analyzePackageRequest({ spec, ecosystem: 'npm' }, { timeoutMs: options.timeoutMs ?? 5000 });
    evaluated.push(result);
  }

  for (const result of evaluated) {
    if (result?.decision?.decision && result.decision.decision !== 'ALLOW') {
      return {
        ok: false,
        mode: 'sandbox-blocked',
        evaluated,
        executed: false,
        decision: result.decision
      };
    }
  }

  const sanitizedSpecs = installSpecs.map((item) => item.replace(/'/g, "'\\''"));
  const command = `npm install ${sanitizedSpecs.map((item) => `'${item}'`).join(' ')}`;
  const result = spawnSync(
    'docker',
    [
      'run',
      '--rm',
      '-v',
      `${process.cwd()}:/app:ro`,
      'node:20-alpine',
      'sh',
      '/app/sandbox/entrypoint.sh',
      'sh',
      '-lc',
      command
    ],
    {
      stdio: 'inherit',
      env: process.env
    }
  );

  return {
    ok: result.status === 0,
    mode: 'docker',
    evaluated,
    executed: true,
    exitCode: result.status ?? 1
  };
}

export function buildSandboxCommand(specs = []) {
  const installSpecs = (specs ?? []).filter(Boolean);
  const sanitizedSpecs = installSpecs.map((item) => item.replace(/'/g, "'\\''"));

  return {
    args: [
      'run',
      '--rm',
      '-it',
      '-v',
      `${process.cwd()}:/app:ro`,
      'node:20-alpine',
      'sh',
      '/app/sandbox/entrypoint.sh'
    ],
    installCommand: `npm install ${sanitizedSpecs.map((item) => `'${item}'`).join(' ')}`
  };
}
