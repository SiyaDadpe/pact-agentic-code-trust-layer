import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import assert from 'node:assert/strict';
import { askYesNo, canPrompt, readApprovals, reviewWarnings } from '../src/review.js';

function tempApprovals() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pact-review-')), 'approvals.json');
}

function result(name, version, action, reason = 'warn: install_script_requires_review') {
  return {
    request: { full_name: name },
    registryResult: { resolvedVersion: version },
    decision: { decision: action, reason, requested_package: { name, version } }
  };
}

const quiet = () => {};

test('one question covers all warned packages; yes approves and remembers each exact version', async () => {
  const file = tempApprovals();
  const results = [result('gatsby', '3.11.0', 'WARN'), result('left-pad', '1.3.0', 'WARN'), result('react', '19.0.0', 'ALLOW')];
  let questions = 0;
  const review = await reviewWarnings(results, 'WARN', { interactive: true, ask: async () => { questions += 1; return true; }, approvalsFile: file, log: quiet });
  assert.equal(questions, 1);
  assert.equal(review.action, 'ALLOW');
  assert.deepEqual(review.approved.sort(), ['gatsby@3.11.0', 'left-pad@1.3.0']);
  assert.deepEqual(Object.keys(readApprovals(file)).sort(), ['gatsby@3.11.0', 'left-pad@1.3.0']);
  assert.equal(results[0].decision.user_review.status, 'approved');
});

test('no keeps the WARN and remembers nothing', async () => {
  const file = tempApprovals();
  const results = [result('gatsby', '3.11.0', 'WARN')];
  const review = await reviewWarnings(results, 'WARN', { interactive: true, ask: async () => false, approvalsFile: file, log: quiet });
  assert.equal(review.action, 'WARN');
  assert.deepEqual(readApprovals(file), {});
  assert.equal(results[0].decision.user_review.status, 'rejected');
});

test('an approved version is not asked again, but a new version is', async () => {
  const file = tempApprovals();
  await reviewWarnings([result('gatsby', '3.11.0', 'WARN')], 'WARN', { interactive: true, ask: async () => true, approvalsFile: file, log: quiet });

  let asked = false;
  const again = await reviewWarnings([result('gatsby', '3.11.0', 'WARN')], 'WARN', { interactive: true, ask: async () => { asked = true; return false; }, approvalsFile: file, log: quiet });
  assert.equal(asked, false);
  assert.equal(again.action, 'ALLOW');
  assert.deepEqual(again.remembered, ['gatsby@3.11.0']);

  const newVersion = await reviewWarnings([result('gatsby', '3.11.1', 'WARN')], 'WARN', { interactive: true, ask: async () => { asked = true; return false; }, approvalsFile: file, log: quiet });
  assert.equal(asked, true);
  assert.equal(newVersion.action, 'WARN');
});

test('without a terminal the WARN stops and nobody is asked', async () => {
  const file = tempApprovals();
  let asked = false;
  const review = await reviewWarnings([result('gatsby', '3.11.0', 'WARN')], 'WARN', { interactive: false, ask: async () => { asked = true; return true; }, approvalsFile: file, log: quiet });
  assert.equal(asked, false);
  assert.equal(review.action, 'WARN');
});

test('--allow-warn allows this run only and is not remembered', async () => {
  const file = tempApprovals();
  const review = await reviewWarnings([result('gatsby', '3.11.0', 'WARN')], 'WARN', { interactive: false, allowWarn: true, approvalsFile: file, log: quiet });
  assert.equal(review.action, 'ALLOW');
  assert.deepEqual(readApprovals(file), {});
});

test('BLOCK and UNKNOWN are never offered for approval', async () => {
  const file = tempApprovals();
  for (const aggregate of ['BLOCK', 'UNKNOWN']) {
    let asked = false;
    const review = await reviewWarnings([result('evil', '1.0.0', 'WARN'), result('bad', '1.0.0', aggregate)], aggregate, { interactive: true, allowWarn: true, ask: async () => { asked = true; return true; }, approvalsFile: file, log: quiet });
    assert.equal(asked, false);
    assert.equal(review.action, aggregate);
  }
});

test('canPrompt requires a terminal on both ends, no --json, and no CI', () => {
  const tty = { isTTY: true };
  assert.equal(canPrompt({ stdin: tty, stdout: tty, env: {} }), true);
  assert.equal(canPrompt({ stdin: {}, stdout: tty, env: {} }), false);
  assert.equal(canPrompt({ stdin: tty, stdout: tty, env: { CI: 'true' } }), false);
  assert.equal(canPrompt({ json: true, stdin: tty, stdout: tty, env: {} }), false);
});

test('askYesNo defaults to no: Enter, other text, or closed input', async () => {
  for (const [typed, expected] of [['y\n', true], ['yes\n', true], ['\n', false], ['maybe\n', false]]) {
    const input = new PassThrough();
    const answer = askYesNo('? ', { input, output: new PassThrough() });
    input.end(typed);
    assert.equal(await answer, expected);
  }
  const closed = new PassThrough();
  const answer = askYesNo('? ', { input: closed, output: new PassThrough() });
  closed.end();
  assert.equal(await answer, false);
});
