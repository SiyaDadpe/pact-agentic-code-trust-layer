import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

// Human review of WARN decisions.
// A WARN stops the command unless a person approves it. Approvals are remembered per exact
// version (name@version), so the same package is not asked about twice, while a new version
// of it is checked again. BLOCK and UNKNOWN decisions are never offered for approval.

export function approvalsPath() {
  return process.env.PACT_APPROVALS_FILE
    ?? path.join(process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), '.config'), 'pact', 'approvals.json');
}

export function readApprovals(filePath = approvalsPath()) {
  if (!fs.existsSync(filePath)) {
    return {};
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8')).approved ?? {};
  } catch {
    return {};
  }
}

export function recordApprovals(entries, filePath = approvalsPath()) {
  const approved = readApprovals(filePath);
  const at = new Date().toISOString();
  for (const entry of entries) {
    approved[entry.key] = { approved_at: at, reason: entry.reason };
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify({ approved }, null, 2)}\n`, 'utf8');
}

// Exact name@version of the package that would be installed; null when the version is unknown.
export function approvalKey(result) {
  const name = result?.request?.full_name ?? result?.decision?.requested_package?.name;
  const version = result?.registryResult?.resolvedVersion ?? result?.decision?.requested_package?.version;
  return name && version ? `${name}@${version}` : null;
}

// Prompt only when a person is at the terminal. Machine use (--json, CI, an agent without a TTY)
// keeps WARN as a stop unless --allow-warn is given explicitly.
export function canPrompt({ json = false, stdin = process.stdin, stdout = process.stdout, env = process.env } = {}) {
  return !json && Boolean(stdin.isTTY) && Boolean(stdout.isTTY) && !env.CI;
}

export function askYesNo(question, { input = process.stdin, output = process.stderr } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input, output });
    let answered = false;
    rl.question(question, (answer) => {
      answered = true;
      rl.close();
      resolve(/^y(es)?$/i.test(String(answer).trim()));
    });
    rl.on('close', () => {
      if (!answered) {
        resolve(false);
      }
    });
  });
}

// Applies remembered approvals and, if needed, asks once for all remaining warnings.
// Returns the action after review: 'ALLOW' if every warning is approved, otherwise the input aggregate.
export async function reviewWarnings(results, aggregate, options = {}) {
  const {
    interactive = false,
    allowWarn = false,
    ask = askYesNo,
    approvalsFile = approvalsPath(),
    verb = 'Continue',
    log = (line) => console.error(line)
  } = options;

  if (aggregate !== 'WARN') {
    return { action: aggregate, approved: [], remembered: [], asked: false };
  }

  const approvals = readApprovals(approvalsFile);
  const warned = results.filter((result) => result.decision?.decision === 'WARN');
  const remembered = warned.filter((result) => approvals[approvalKey(result)]);
  const pending = warned.filter((result) => !approvals[approvalKey(result)]);

  for (const result of remembered) {
    result.decision.user_review = { status: 'previously_approved', key: approvalKey(result) };
  }
  if (!pending.length) {
    return { action: 'ALLOW', approved: [], remembered: remembered.map(approvalKey), asked: false };
  }

  let approve = allowWarn;
  let asked = false;
  if (!approve && interactive) {
    log('');
    log(`PACT: ${pending.length} package${pending.length === 1 ? '' : 's'} need${pending.length === 1 ? 's' : ''} your review:`);
    for (const result of pending) {
      log(`  ! ${approvalKey(result) ?? result.decision.requested_package.name}  ${result.decision.reason}`);
    }
    approve = await ask(`${verb} anyway? [y/N] `);
    asked = true;
  }

  if (!approve) {
    for (const result of pending) {
      result.decision.user_review = { status: asked ? 'rejected' : 'not_reviewed', key: approvalKey(result) };
    }
    return { action: 'WARN', approved: [], remembered: remembered.map(approvalKey), asked };
  }

  const entries = pending
    .map((result) => ({ key: approvalKey(result), reason: result.decision.reason }))
    .filter((entry) => entry.key);
  // Only an answer typed by a person is remembered; --allow-warn applies to this run only.
  if (asked && entries.length) {
    recordApprovals(entries, approvalsFile);
  }
  for (const result of pending) {
    result.decision.user_review = { status: allowWarn && !asked ? 'allowed_by_flag' : 'approved', key: approvalKey(result) };
  }
  return { action: 'ALLOW', approved: entries.map((entry) => entry.key), remembered: remembered.map(approvalKey), asked };
}
