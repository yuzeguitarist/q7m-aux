import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildReport, callback, captureCommand, childEnvironment, cleanupParts, combinePartReports, openPart, openResult, openTask, runScript, sealPart, sealResult, sealTask, validateParameters, validateTask } from './relay.mjs';

const key = randomBytes(32).toString('base64');
const otherKey = randomBytes(32).toString('base64');
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const task = { version: 1, id: 'a'.repeat(32), group: 'd'.repeat(64), repository: 'owner/source', sha: 'b'.repeat(40),
  status_sha: 'c'.repeat(40), platform: 'linux', scope: 'app', request_run_id: '123', request_run_attempt: '1', context: 'CI / Linux' };

const partitionedTask = { ...task, platform: 'macos', kind: 'checks', context: 'CI / macOS' };
const publicRun = { public_run_id: '456', public_run_attempt: '3' };
const partReport = (part, change = {}) => buildReport(partitionedTask,
  { exit_code: 0, log: `private part ${part}\n`, ...change }, publicRun);
const openedPart = (part, report = partReport(part)) =>
  openPart(sealPart(part, report, key), key, partitionedTask, publicRun, part);

test('part artifacts authenticate encrypted reports with a separate key domain and fresh IV', () => {
  for (const part of [0, 1, 2]) {
    const report = partReport(part);
    const payload = sealPart(part, report, key);
    assert.deepEqual(openPart(payload, key, partitionedTask, publicRun, part),
      { domain: 'part-v1', part, report });
    assert.equal(payload.includes(Buffer.from(report.log)), false);
    assert.equal(payload.includes(Buffer.from(task.repository)), false);
    assert.notDeepEqual(payload, sealPart(part, report, key));
    assert.throws(() => openPart(payload, otherKey, partitionedTask, publicRun, part));
    assert.throws(() => openPart(payload, key, partitionedTask, publicRun, (part + 1) % 3));
    const altered = JSON.parse(payload);
    altered.tag = randomBytes(16).toString('base64url');
    assert.throws(() => openPart(Buffer.from(JSON.stringify(altered)), key, partitionedTask, publicRun, part));
    const taskEnvelope = Buffer.from(sealTask({ domain: 'part-v1', part, report }, key), 'base64url');
    assert.throws(() => openPart(taskEnvelope, key, partitionedTask, publicRun, part));
  }
});

test('every part report identity field and current public attempt must match', () => {
  const report = partReport(0);
  for (const field of Object.keys(report).filter(field => !['exit_code', 'log', 'outputs'].includes(field))) {
    const altered = { ...report, [field]: field === 'version' ? 2 : `${report[field]}x` };
    assert.throws(() => openPart(sealPart(0, altered, key), key, partitionedTask, publicRun, 0), field);
  }
  const payload = sealPart(0, report, key);
  assert.throws(() => openPart(payload, key, partitionedTask, { ...publicRun, public_run_attempt: '4' }, 0));
  assert.throws(() => openPart(payload, key, { ...partitionedTask, sha: 'e'.repeat(40) }, publicRun, 0));
  assert.throws(() => openPart(payload, key, task, publicRun, 0));
  assert.throws(() => sealPart(3, report, key));
  assert.throws(() => openPart(Buffer.alloc(16 * 1024 * 1024 + 1), key, partitionedTask, publicRun, 0));
});

test('part report shape, exit status, log and metadata limits fail closed', () => {
  const report = partReport(0);
  for (const change of [
    { exit_code: -1 }, { exit_code: 256 }, { exit_code: 0.5 }, { exit_code: '0' },
    { log: null }, { log: 'x'.repeat(8 * 1024 * 1024) },
    { log: '\0'.repeat(1_400_000) }, { outputs: null }, { outputs: [] },
    { outputs: { large: 'x'.repeat(64 * 1024) } }, { unexpected: 'value' },
  ]) {
    assert.throws(() => openPart(sealPart(0, { ...report, ...change }, key), key, partitionedTask, publicRun, 0));
  }
  assert.throws(() => validateParameters({ CI_EXECUTION_PART: '1' }));
});

test('combination requires all three unique authenticated parts and propagates every failure', () => {
  const first = openedPart(0);
  const second = openedPart(1);
  const third = openedPart(2);
  assert.throws(() => combinePartReports([], partitionedTask, publicRun));
  assert.throws(() => combinePartReports([first], partitionedTask, publicRun));
  assert.throws(() => combinePartReports([first, second], partitionedTask, publicRun));
  assert.throws(() => combinePartReports([first, second, first], partitionedTask, publicRun));
  assert.throws(() => combinePartReports([first, second, { ...third, part: 3 }], partitionedTask, publicRun));
  assert.throws(() => combinePartReports([first, second, { ...third, domain: 'wrong' }], partitionedTask, publicRun));
  assert.throws(() => combinePartReports([first, second, third], partitionedTask, { ...publicRun, public_run_attempt: '4' }));
  assert.throws(() => combinePartReports([first, second, third], { ...partitionedTask, kind: 'site' }, publicRun));
  for (const failed of [0, 1, 2]) {
    const report = combinePartReports([0, 1, 2].map(part =>
      openedPart(part, partReport(part, { exit_code: failed === part ? 9 : 0 }))), partitionedTask, publicRun);
    assert.equal(report.exit_code, 9);
    assert.match(report.log, /=== Part 0 ===\nprivate part 0/);
    assert.match(report.log, /=== Part 1 ===\nprivate part 1/);
    assert.match(report.log, /=== Part 2 ===\nprivate part 2/);
    assert.deepEqual(report.outputs, {});
  }
});

test('combined binary and Unicode logs fit the raw, JSON and encrypted result budgets', () => {
  for (const log of ['x'.repeat(8 * 1024 * 1024 - 2), '\0'.repeat(1_300_000), '\u{1f600}'.repeat(1_500_000)]) {
    const parts = [0, 1, 2].map(part => openedPart(part, partReport(part, { log })));
    const report = combinePartReports(parts.reverse(), partitionedTask, publicRun);
    assert.match(report.log, /Log truncated/);
    assert.ok(Buffer.byteLength(report.log) <= 8 * 1024 * 1024);
    assert.ok(Buffer.byteLength(JSON.stringify(report.log)) <= 8 * 1024 * 1024);
    assert.deepEqual(openResult(sealResult(report, publicKey, key), privateKey, key), report);
  }
});

test('combine CLI emits only encrypted complete or failure reports for missing and corrupt artifacts', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'relay-combine-'));
  try {
    const files = [0, 1, 2].map(part => join(directory, 'parts', `part-${part}`, 'part.bin'));
    for (const file of files) await mkdir(join(file, '..'), { recursive: true });
    for (const mode of ['missing', 'corrupt', 'wrong-attempt', 'complete']) {
      for (const part of [0, 1, 2]) await writeFile(files[part], sealPart(part, partReport(part), key));
      if (mode === 'missing') await rm(files[2]);
      if (mode === 'corrupt') await writeFile(files[0], 'not an artifact');
      if (mode === 'wrong-attempt') await writeFile(files[1],
        sealPart(1, { ...partReport(1), public_run_attempt: '2' }, key));
      const output = execFileSync(process.execPath, [fileURLToPath(new URL('./relay.mjs', import.meta.url)), 'combine'], {
        encoding: 'utf8', env: { ...childEnvironment(process.env), RUNNER_TEMP: directory,
          TASK_PAYLOAD: sealTask(partitionedTask, key), TASK_PLATFORM: 'macos', TASK_GROUP: task.group,
          CI_SOURCE_REPOSITORY: task.repository, CI_RELAY_KEY: key, CI_RESULT_PUBLIC_KEY: publicKey,
          GITHUB_RUN_ID: publicRun.public_run_id, GITHUB_RUN_ATTEMPT: publicRun.public_run_attempt },
      });
      assert.equal(output, '');
      const payload = await readFile(join(directory, 'result', 'payload.bin'));
      const report = openResult(payload, privateKey, key);
      assert.equal(report.exit_code, mode === 'complete' ? 0 : 125);
      assert.equal(report.public_run_attempt, publicRun.public_run_attempt);
      assert.equal(payload.includes(Buffer.from('private part')), false);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('unassigned parts never execute legacy source and untrusted markers cannot enable partitioning', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'relay-part-marker-'));
  const source = join(directory, 'source');
  const marker = join(source, '.github/ci/parts');
  try {
    await mkdir(join(source, '.github/ci'), { recursive: true });
    await writeFile(join(source, '.github/ci/run.sh'), 'exit 99\n');
    for (const content of [undefined, '1', '4', '2'.repeat(17)]) {
      if (content !== undefined) await writeFile(marker, content);
      for (const part of [1, 2]) {
        const outcome = await runScript(source, 'macos', 'app', { part });
        assert.equal(outcome.exit_code, 0);
        assert.match(outcome.log, /no assigned execution part/);
      }
    }
    await rm(marker);
    const target = join(directory, 'marker');
    await writeFile(target, '2\n');
    await symlink(target, marker);
    assert.equal((await runScript(source, 'macos', 'app', { part: 1 })).exit_code, 0);
    await rm(marker);
    await writeFile(marker, '2\n');
    assert.equal((await runScript(source, 'macos', 'app', { part: 2 })).exit_code, 0);
    await assert.rejects(runScript(source, 'linux', 'app', { part: 0 }), /partitioned task/);
    await assert.rejects(runScript(source, 'macos', 'app', { part: '1' }), /execution part/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('part cleanup uses only current-run artifact names and leaves final payloads intact', async () => {
  const values = { GITHUB_REPOSITORY: 'owner/executor', GITHUB_RUN_ID: '456', GITHUB_TOKEN: 'job-token' };
  const prior = Object.fromEntries(Object.keys(values).map(name => [name, process.env[name]]));
  const originalFetch = globalThis.fetch;
  const deleted = [];
  Object.assign(process.env, values);
  try {
    globalThis.fetch = async (url, options) => {
      assert.equal(options.headers.Authorization, 'Bearer job-token');
      if (options.method === 'DELETE') {
        deleted.push(url);
        return new Response(null, { status: 204 });
      }
      assert.match(url, /^https:\/\/api\.github\.com\/repos\/owner\/executor\/actions\/runs\/456\/artifacts\?per_page=100&page=[12]$/);
      const artifacts = url.endsWith('page=1')
        ? [{ id: 11, name: 'part-0' }, { id: 12, name: 'payload' },
          ...Array.from({ length: 98 }, (_, index) => ({ id: 100 + index, name: 'other' }))]
        : [{ id: 22, name: 'part-1' }, { id: 23, name: 'part-2' }, { id: 24, name: 'part-0-other' }, { id: 25, name: 'part-9' }];
      return Response.json({ artifacts });
    };
    await cleanupParts();
    assert.deepEqual(deleted, [
      'https://api.github.com/repos/owner/executor/actions/artifacts/11',
      'https://api.github.com/repos/owner/executor/actions/artifacts/22',
      'https://api.github.com/repos/owner/executor/actions/artifacts/23',
    ]);
    for (const change of [{ GITHUB_REPOSITORY: '../other' }, { GITHUB_RUN_ID: '0' }, { GITHUB_TOKEN: '' }]) {
      Object.assign(process.env, values, change);
      await assert.rejects(cleanupParts(), /Invalid cleanup context/);
    }
    Object.assign(process.env, values);
    globalThis.fetch = async () => new Response(null, { status: 403 });
    await assert.rejects(cleanupParts(), /Remote request failed/);
    globalThis.fetch = async () => { throw new Error('network unavailable'); };
    await assert.rejects(cleanupParts(), /network unavailable/);
    globalThis.fetch = async () => Response.json({ artifacts: [{ id: '../12', name: 'part-0' }] });
    await assert.rejects(cleanupParts(), /Invalid artifact id/);
  } finally {
    globalThis.fetch = originalFetch;
    for (const [name, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

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
    GITHUB_RUN_ID: '456', GITHUB_RUN_ATTEMPT: '3', CI_CALLBACK_TOKEN: 'test-token',
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
    const source = fileURLToPath(new URL('./fixtures/source', import.meta.url));
    const result = await captureCommand('bash', [join(source, '.github/ci/run.sh'), 'linux'], source,
      { ...childEnvironment(process.env), CI_SCOPE: 'source' });
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
  const source = fileURLToPath(new URL('./fixtures/source', import.meta.url));
  const outcome = await captureCommand('bash', [join(source, '.github/ci/run.sh'), 'linux'], source,
    { ...childEnvironment(process.env), CI_SCOPE: 'source', LARGE_OUTPUT: '1' });
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
