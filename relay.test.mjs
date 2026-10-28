import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildReport, callback, childEnvironment, openResult, openTask, runScript, sealResult, sealTask, validateParameters, validateTask } from './relay.mjs';

const key = randomBytes(32).toString('base64');
const otherKey = randomBytes(32).toString('base64');
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const task = { version: 1, id: 'a'.repeat(32), group: 'd'.repeat(64), repository: 'owner/source', sha: 'b'.repeat(40),
  status_sha: 'c'.repeat(40), platform: 'linux', scope: 'app', request_run_id: '123', request_run_attempt: '1', context: 'CI / Linux' };

test('task encryption hides metadata and authenticates it', () => {
  const payload = sealTask(task, key);
  assert.deepEqual(openTask(payload, key), task);
  assert.equal(payload.includes(task.repository), false);
  assert.throws(() => openTask(payload, otherKey));
  const envelope = JSON.parse(Buffer.from(payload, 'base64url'));
  envelope.data = Buffer.from('modified').toString('base64url');
  assert.throws(() => openTask(Buffer.from(JSON.stringify(envelope)).toString('base64url'), key));
});

test('reports require the private key and relay authentication', () => {
  const report = { ...task, exit_code: 7, log: 'private output\n::error::not public\n' };
  const payload = sealResult(report, publicKey, key);
  assert.deepEqual(openResult(payload, privateKey, key), report);
  assert.equal(payload.includes(Buffer.from(report.log)), false);
  assert.throws(() => openResult(payload, privateKey, otherKey));
  const forged = sealResult({ ...report, exit_code: 0 }, publicKey, otherKey);
  assert.throws(() => openResult(forged, privateKey, key));
  const altered = JSON.parse(payload);
  altered.tag = randomBytes(16).toString('base64url');
  assert.throws(() => openResult(Buffer.from(JSON.stringify(altered)), privateKey, key));
});

test('task validation binds repository, platform, commit and request', () => {
  assert.equal(validateTask(task, 'owner/source', 'linux'), task);
  for (const change of [
    { version: 2 }, { id: '../bad' }, { group: 'invalid' }, { sha: 'main' }, { status_sha: 'main' }, { repository: 'elsewhere/source' },
    { platform: 'macos' }, { scope: 'arbitrary' }, { request_run_id: '1; echo bad' }, { context: '\n::error::bad' },
    { request_run_attempt: undefined }, { request_run_attempt: '0' }, { request_run_attempt: '1000000' },
  ]) assert.throws(() => validateTask({ ...task, ...change }, 'owner/source', 'linux'));
  assert.throws(() => openTask('a'.repeat(50_000), key));
});

test('parameters cannot replace credentials, shell controls or result paths', () => {
  assert.deepEqual(validateParameters({ API_TOKEN: 'private', CI_SITE_MODE: 'preview', CI_SITE_ALIAS: 'pabc', CI_PULL_REQUEST: '12' }),
    { API_TOKEN: 'private', CI_SITE_MODE: 'preview', CI_SITE_ALIAS: 'pabc', CI_PULL_REQUEST: '12' });
  for (const name of ['CI_RELAY_KEY', 'CI_SOURCE_TOKEN', 'CI_RESULT_METADATA_PATH', 'CI_SOURCE_SHA',
    'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'RUNNER_TEMP', 'NODE_OPTIONS', 'PATH', 'HOME', 'LD_PRELOAD',
    'DYLD_INSERT_LIBRARIES', 'BASH_ENV', 'ENV', 'PYTHONPATH', 'lowercase']) {
    assert.throws(() => validateParameters({ [name]: 'unsafe' }));
  }
  assert.throws(() => validateParameters({ API_TOKEN: 'x'.repeat(8193) }));
  assert.throws(() => validateParameters({ FIRST: 'x'.repeat(8192), SECOND: 'x'.repeat(8192) }));
});

test('reports omit secret parameters and retain metadata inside encryption', () => {
  const enriched = { ...task, kind: 'site', parameters: { API_TOKEN: 'top-secret-parameter' } };
  const report = buildReport(enriched, { exit_code: 0, log: 'complete', outputs: { url: 'https://example.test/preview' } },
    { public_run_id: '1234', public_run_attempt: '1' });
  assert.equal('parameters' in report, false);
  assert.equal(report.request_run_attempt, '1');
  assert.equal(JSON.stringify(report).includes('top-secret-parameter'), false);
  const encrypted = sealResult(report, publicKey, key);
  assert.equal(encrypted.includes(Buffer.from('example.test')), false);
  assert.deepEqual(openResult(encrypted, privateKey, key), report);
});

test('callback binds the private request attempt and task kind', async () => {
  const enriched = { ...task, kind: 'site', request_run_attempt: '2' };
  const values = {
    TASK_PAYLOAD: sealTask(enriched, key), CI_RELAY_KEY: key,
    CI_SOURCE_REPOSITORY: task.repository, TASK_PLATFORM: task.platform, TASK_GROUP: task.group,
    GITHUB_RUN_ID: '456', GITHUB_RUN_ATTEMPT: '3', CI_SOURCE_TOKEN: 'test-token',
  };
  const prior = Object.fromEntries(Object.keys(values).map(name => [name, process.env[name]]));
  const originalFetch = globalThis.fetch;
  let request;
  Object.assign(process.env, values);
  globalThis.fetch = async (url, options) => {
    request = { url, body: JSON.parse(options.body) };
    return new Response(null, { status: 204 });
  };
  try {
    await callback();
    assert.equal(request.url, `https://api.github.com/repos/${task.repository}/dispatches`);
    assert.deepEqual(request.body, { event_type: 'ci-relay-result', client_payload: {
      run_id: '456', run_attempt: '3', id: task.id, request_run_id: '123',
      request_run_attempt: '2', kind: 'site', platform: 'linux',
    } });
  } finally {
    globalThis.fetch = originalFetch;
    for (const [name, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('child processes receive no relay or Actions credentials', () => {
  const env = childEnvironment({ PATH: '/bin', HOME: '/tmp', CI_SOURCE_TOKEN: 'secret',
    CI_RELAY_KEY: 'secret', GITHUB_TOKEN: 'secret', ACTIONS_RUNTIME_TOKEN: 'secret',
    GITHUB_ENV: '/tmp/env', GITHUB_OUTPUT: '/tmp/output', TASK_PAYLOAD: 'secret' });
  assert.deepEqual(env, { CI: 'true', PATH: '/bin', HOME: '/tmp' });
});

test('execution captures raw workflow commands privately and propagates failures', async () => {
  process.env.CI_SOURCE_TOKEN = 'must-not-reach-child';
  process.env.CI_RELAY_KEY = 'must-not-reach-child';
  try {
    const result = await runScript(fileURLToPath(new URL('./fixtures/source', import.meta.url)), 'linux', 'source');
    assert.equal(result.exit_code, 9);
    assert.match(result.log, /::error::private diagnostic/);
    assert.match(result.log, /platform=linux scope=source/);
    assert.equal(result.log.includes('must-not-reach-child'), false);
  } finally {
    delete process.env.CI_SOURCE_TOKEN;
    delete process.env.CI_RELAY_KEY;
  }
});

test('binary-heavy oversized logs remain within encrypted report limits', async () => {
  const outcome = await runScript(fileURLToPath(new URL('./fixtures/source', import.meta.url)), 'linux', 'source',
    { parameters: { LARGE_OUTPUT: '1' } });
  assert.equal(outcome.exit_code, 0);
  assert.match(outcome.log, /Log truncated/);
  assert.ok(Buffer.byteLength(outcome.log) < 8 * 1024 * 1024 + 1024);
  const report = buildReport(task, outcome, { public_run_id: '1234', public_run_attempt: '1' });
  assert.deepEqual(openResult(sealResult(report, publicKey, key), privateKey, key), report);
});

for (const [signal, expectedCode] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  test(`${signal} cancels the detached process group immediately`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'relay-cancel-'));
    const marker = join(directory, 'ready');
    const runner = spawn(process.execPath, [fileURLToPath(new URL('./fixtures/wait-runner.mjs', import.meta.url)), marker],
      { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    let errors = '';
    runner.stdout.on('data', chunk => { output += chunk; });
    runner.stderr.on('data', chunk => { errors += chunk; });
    const closed = new Promise((resolveClose, reject) => {
      runner.on('error', reject);
      runner.on('close', (code, receivedSignal) => resolveClose({ code, receivedSignal }));
    });
    const deadline = setTimeout(() => runner.kill('SIGKILL'), 5000);
    let descendants = [];
    try {
      const readyDeadline = Date.now() + 3000;
      while (!descendants.length && Date.now() < readyDeadline) {
        try { descendants = (await readFile(marker, 'utf8')).trim().split(' ').map(Number); } catch {}
        if (!descendants.length) await new Promise(resolveDelay => setTimeout(resolveDelay, 20));
      }
      assert.equal(descendants.length, 2, 'controlled descendant must start before cancellation');
      const started = Date.now();
      runner.kill(signal);
      assert.deepEqual(await closed, { code: 0, receivedSignal: null });
      assert.ok(Date.now() - started < 2000, 'cancellation must finish within two seconds');
      assert.equal(errors, '');
      const received = JSON.parse(output);
      assert.equal(received.result.exit_code, expectedCode);
      assert.equal(received.interruptListeners, 0);
      assert.equal(received.terminateListeners, 0);
      for (const pid of descendants) {
        let status = '';
        try { status = execFileSync('ps', ['-p', String(pid), '-o', 'stat='], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch {}
        assert.ok(!status || status.startsWith('Z'), `descendant ${pid} must no longer be running`);
      }
    } finally {
      clearTimeout(deadline);
      if (runner.exitCode === null && runner.signalCode === null) runner.kill('SIGKILL');
      if (descendants[0]) {
        try { process.kill(-descendants[0], 'SIGKILL'); } catch {}
      }
      await rm(directory, { recursive: true, force: true });
    }
  });
}
