import {
  constants, createCipheriv, createDecipheriv, createHmac, privateDecrypt,
  publicEncrypt, randomBytes, timingSafeEqual,
} from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstat, mkdir, open, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { isolateMac } from './mac-runner.mjs';

const MAX_PAYLOAD = 48 * 1024;
const MAX_LOG = 8 * 1024 * 1024;
const MAX_REPORT = 16 * 1024 * 1024;
const encode = value => Buffer.from(value).toString('base64url');
const decode = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid encoding');
  return Buffer.from(value, 'base64url');
};

function sharedKey(value) {
  const key = Buffer.from(value ?? '', 'base64');
  if (key.length !== 32) throw new Error('Invalid key');
  return key;
}

function encrypt(value, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
  return { iv: encode(iv), tag: encode(cipher.getAuthTag()), data: encode(data) };
}

function decrypt(value, key) {
  const iv = decode(value.iv);
  const tag = decode(value.tag);
  if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid envelope');
  const cipher = createDecipheriv('aes-256-gcm', key, iv);
  cipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([cipher.update(decode(value.data)), cipher.final()]).toString('utf8'));
}

export function sealTask(task, key) {
  return encode(JSON.stringify({ v: 1, ...encrypt(task, sharedKey(key)) }));
}

export function openTask(payload, key) {
  if (typeof payload !== 'string' || payload.length > MAX_PAYLOAD) throw new Error('Invalid payload');
  const value = JSON.parse(decode(payload).toString('utf8'));
  if (value.v !== 1) throw new Error('Invalid version');
  return decrypt(value, sharedKey(key));
}

function signedEnvelope(value) {
  return JSON.stringify({ v: value.v, key: value.key, iv: value.iv, tag: value.tag, data: value.data });
}

export function sealResult(report, publicKey, key) {
  const contentKey = randomBytes(32);
  const value = {
    v: 1,
    key: encode(publicEncrypt({ key: publicKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, contentKey)),
    ...encrypt(report, contentKey),
  };
  value.mac = encode(createHmac('sha256', sharedKey(key)).update(signedEnvelope(value)).digest());
  return Buffer.from(JSON.stringify(value));
}

export function openResult(payload, privateKey, key) {
  if (Buffer.byteLength(payload) > MAX_REPORT) throw new Error('Invalid report size');
  const value = JSON.parse(Buffer.from(payload).toString('utf8'));
  if (value.v !== 1) throw new Error('Invalid version');
  const expected = createHmac('sha256', sharedKey(key)).update(signedEnvelope(value)).digest();
  const actual = decode(value.mac);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new Error('Invalid authentication');
  const contentKey = privateDecrypt({ key: privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, decode(value.key));
  if (contentKey.length !== 32) throw new Error('Invalid key');
  return decrypt(value, contentKey);
}

export function validateTask(task, repository, platform) {
  if (!task || task.version !== 1 || task.repository !== repository
      || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '')
      || !/^[0-9a-f]{32}$/.test(task.id ?? '')
      || !/^[0-9a-f]{64}$/.test(task.group ?? '')
      || !/^[0-9a-f]{40}$/.test(task.sha ?? '')
      || !/^[0-9a-f]{40}$/.test(task.status_sha ?? '')
      || !['linux', 'macos'].includes(platform) || task.platform !== platform
      || !['app', 'source'].includes(task.scope)
      || (platform === 'macos' && task.scope !== 'app')
      || !['checks', 'site'].includes(task.kind ?? 'checks')
      || (task.kind === 'site' && platform !== 'linux')
      || !/^[1-9][0-9]{0,19}$/.test(task.request_run_id ?? '')
      || !/^[1-9][0-9]{0,5}$/.test(task.request_run_attempt ?? '')
      || typeof task.context !== 'string' || !/^[A-Za-z0-9 /_.-]{1,100}$/.test(task.context)) {
    throw new Error('Invalid task');
  }
  validateParameters(task.parameters ?? {});
  return task;
}

export function validateParameters(parameters) {
  if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)
      || Buffer.byteLength(JSON.stringify(parameters)) > 16 * 1024) throw new Error('Invalid parameters');
  const exceptions = new Set(['CI_SITE_MODE', 'CI_SITE_ALIAS', 'CI_PULL_REQUEST']);
  for (const [name, value] of Object.entries(parameters)) {
    if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(name) || typeof value !== 'string' || value.length > 8192
        || (!exceptions.has(name) && /^(CI_|GITHUB|ACTIONS|RUNNER|NODE_|LD_|DYLD_|BASH|PYTHON|PERL|RUBY|NPM_CONFIG)|^(PATH|HOME|SHELL|ENV|SHELLOPTS|IFS|CDPATH|ZDOTDIR|TMPDIR|TMP|TEMP)$/.test(name))) {
      throw new Error('Invalid parameters');
    }
  }
  return parameters;
}

export function buildReport(task, outcome, publicRun) {
  return {
    version: task.version, id: task.id, group: task.group, repository: task.repository, sha: task.sha,
    status_sha: task.status_sha, platform: task.platform, scope: task.scope,
    kind: task.kind ?? 'checks', request_run_id: task.request_run_id,
    request_run_attempt: task.request_run_attempt, context: task.context,
    exit_code: outcome.exit_code, log: outcome.log, outputs: outcome.outputs ?? {},
    public_run_id: publicRun.public_run_id, public_run_attempt: publicRun.public_run_attempt,
  };
}

function validatePartNumber(part) {
  if (part !== 0 && part !== 1 && part !== 2) throw new Error('Invalid execution part');
  return part;
}

function validatePartTask(task) {
  validateTask(task, task.repository, 'macos');
  if ((task.kind ?? 'checks') !== 'checks') throw new Error('Invalid partitioned task');
}

function validatePartReport(report, task, publicRun) {
  const expected = buildReport(task, { exit_code: 0, log: '' }, publicRun);
  if (!report || typeof report !== 'object' || Array.isArray(report)
      || Object.keys(report).length !== Object.keys(expected).length
      || !Number.isInteger(report.exit_code) || report.exit_code < 0 || report.exit_code > 255
      || typeof report.log !== 'string' || Buffer.byteLength(report.log) > MAX_LOG
      || Buffer.byteLength(JSON.stringify(report.log)) > MAX_LOG
      || !report.outputs || typeof report.outputs !== 'object' || Array.isArray(report.outputs)
      || Buffer.byteLength(JSON.stringify(report.outputs)) > 64 * 1024) throw new Error('Invalid part report');
  for (const field of Object.keys(expected)) {
    if (!['exit_code', 'log', 'outputs'].includes(field) && report[field] !== expected[field]) {
      throw new Error('Part report identity mismatch');
    }
  }
}

function partKey(key, id, run, attempt) {
  return createHmac('sha256', sharedKey(key)).update(`part-v1:${id}:${run}:${attempt}`).digest();
}

export function sealPart(part, report, key) {
  validatePartNumber(part);
  const result = Buffer.from(JSON.stringify({ v: 1, ...encrypt({ domain: 'part-v1', part, report },
    partKey(key, report.id, report.public_run_id, report.public_run_attempt)) }));
  if (result.length > MAX_REPORT) throw new Error('Invalid part size');
  return result;
}

export function openPart(payload, key, task, publicRun, part) {
  validatePartNumber(part);
  validatePartTask(task);
  if (Buffer.byteLength(payload) > MAX_REPORT) throw new Error('Invalid part size');
  const envelope = JSON.parse(Buffer.from(payload).toString('utf8'));
  if (envelope.v !== 1) throw new Error('Invalid part version');
  const value = decrypt(envelope,
    partKey(key, task.id, publicRun.public_run_id, publicRun.public_run_attempt));
  if (value.domain !== 'part-v1' || value.part !== part) throw new Error('Invalid part identity');
  validatePartReport(value.report, task, publicRun);
  return value;
}

export function combinePartReports(parts, task, publicRun) {
  validatePartTask(task);
  if (!Array.isArray(parts) || parts.length !== 3
      || new Set(parts.map(value => value?.part)).size !== 3) throw new Error('Missing or duplicate parts');
  const reports = [0, 1, 2].map(part => {
    const value = parts.find(value => value?.part === part);
    if (!value || value.domain !== 'part-v1') throw new Error('Invalid part identity');
    validatePartReport(value.report, task, publicRun);
    return value.report;
  });
  return buildReport(task, {
    exit_code: reports.find(report => report.exit_code !== 0)?.exit_code ?? 0,
    log: boundedLog(reports.map((report, part) => `=== Part ${part} ===\n${report.log}`).join('\n')),
    outputs: {},
  }, publicRun);
}

async function declaredPartCount(source) {
  const marker = join(source, '.github/ci/parts');
  try {
    const metadata = await lstat(marker);
    if (!metadata.isFile() || metadata.size > 16
        || await realpath(marker) !== join(await realpath(source), '.github/ci/parts')) return 1;
    const value = (await readFile(marker, 'utf8')).trim();
    return value === '2' || value === '3' ? Number(value) : 1;
  } catch (error) {
    if (error.code === 'ENOENT') return 1;
    throw error;
  }
}

function taskFromEnvironment() {
  const task = validateTask(openTask(process.env.TASK_PAYLOAD, process.env.CI_RELAY_KEY),
    process.env.CI_SOURCE_REPOSITORY, process.env.TASK_PLATFORM);
  if (task.group !== process.env.TASK_GROUP) throw new Error('Invalid group');
  return task;
}

async function api(path, options = {}, token = process.env.CI_SOURCE_READ_TOKEN) {
  if (!token) throw new Error('Scoped relay credential is not configured');
  const response = await fetch(`https://api.github.com/${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...options.headers,
    },
    signal: AbortSignal.timeout(180_000),
  });
  if (!response.ok) throw new Error('Remote request failed');
  return response;
}

async function downloadSource(task, destination) {
  const response = await api(`repos/${task.repository}/tarball/${task.sha}`);
  const archive = await open(destination, 'wx', 0o600);
  let size = 0;
  try {
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > 1024 * 1024 * 1024) throw new Error('Archive too large');
      let offset = 0;
      while (offset < chunk.length) {
        const { bytesWritten } = await archive.write(chunk, offset, chunk.length - offset);
        if (!bytesWritten) throw new Error('Archive write failed');
        offset += bytesWritten;
      }
    }
  } finally {
    await archive.close();
  }
}

function command(executable, args, options) {
  return new Promise((resolveCommand, reject) => {
    const child = spawn(executable, args, { ...options, stdio: 'ignore' });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolveCommand() : reject(new Error('Preparation failed')));
  });
}

export function childEnvironment(environment) {
  const allowed = ['PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL',
    'DEVELOPER_DIR', 'SDKROOT', 'SHELL', 'USER', 'LOGNAME'];
  const clean = { CI: 'true' };
  for (const name of allowed) if (environment[name]) clean[name] = environment[name];
  return clean;
}

export async function runScript(source, platform, scope, options = {}) {
  const { kind = 'checks', parameters = {}, sha, metadataPath, trustedSiteScript, part } = options;
  validateParameters(parameters);
  if (part !== undefined) {
    validatePartNumber(part);
    if (platform !== 'macos' || scope !== 'app' || kind !== 'checks') throw new Error('Invalid partitioned task');
  }
  if (kind === 'site' && !trustedSiteScript) throw new Error('Site tasks require a trusted runner script');
  const script = kind === 'site' ? trustedSiteScript : join(source, '.github/ci/run.sh');
  const canonicalSource = await realpath(source);
  const canonicalScript = await realpath(script);
  if (!(await lstat(script)).isFile()
      || (kind !== 'site' && !canonicalScript.startsWith(canonicalSource + sep))) {
    throw new Error('Invalid script');
  }
  const count = part === undefined ? 1 : await declaredPartCount(canonicalSource);
  if (part !== undefined && part >= count) return { exit_code: 0, log: 'Task has no assigned execution part.\n' };
  const partitioned = part !== undefined && count > 1;
  const environment = { ...childEnvironment(process.env), ...parameters, CI_SCOPE: scope,
    ...(kind === 'site' ? { CI_SOURCE_DIRECTORY: canonicalSource } : {}),
    ...(sha ? { CI_SOURCE_SHA: sha } : {}),
    ...(metadataPath ? { CI_RESULT_METADATA_PATH: metadataPath } : {}),
  };
  if (kind === 'site') return captureCommand('bash', [script, platform], source, environment);
  if (platform === 'linux') {
    const name = `cfci-${randomBytes(12).toString('hex')}`;
    try {
      return await captureCommand('docker', [
        'run', '--rm', '--init', '--name', name, '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--user', `${process.getuid()}:${process.getgid()}`,
        '--pids-limit=512', '--memory=6g', '--cpus=2',
        '--mount', `type=bind,source=${canonicalSource},target=/workspace`, '--workdir', '/workspace',
        '--env', 'HOME=/tmp', '--env', 'CI=true', '--env', `CI_SCOPE=${scope}`,
        ...Object.entries(parameters).flatMap(([key, value]) => ['--env', `${key}=${value}`]),
        'python:3.13-bookworm', 'bash', '.github/ci/run.sh', platform,
      ], source, childEnvironment(process.env));
    } finally {
      await command('docker', ['rm', '-f', name], { env: childEnvironment(process.env) }).catch(() => {});
    }
  }
  if (platform !== 'macos') throw new Error('Unsupported execution platform');
  const isolated = await isolateMac(canonicalSource, childEnvironment(process.env));
  return captureIsolated(() => captureCommand('/usr/bin/sudo', [...isolated.args,
      `CI_SCOPE=${scope}`, ...Object.entries(parameters).map(([key, value]) => `${key}=${value}`),
      ...(partitioned ? [`CI_EXECUTION_PART=${part}`] : []),
      '/bin/bash', `${isolated.source}/.github/ci/run.sh`, platform,
    ], '/', childEnvironment(process.env), isolated.stop), isolated.cleanup);
}

// Capturing and cancellation are tested independently of the OS isolation layer.
export async function captureCommand(executable, args, cwd, environment, stop) {
  let logSize = 0;
  const chunks = [];
  let truncated = false;
  const exitCode = await new Promise(resolveRun => {
    const child = spawn(executable, args, {
      cwd, env: environment,
      detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    const keep = chunk => {
      if (logSize < MAX_LOG) chunks.push(chunk.subarray(0, MAX_LOG - logSize));
      logSize += chunk.length;
      if (logSize > MAX_LOG) truncated = true;
    };
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    let interruptedExitCode;
    const interrupt = exitCode => {
      interruptedExitCode ??= exitCode;
      if (stop) void stop().catch(() => {});
      if (child.pid) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch {}
      }
    };
    const onInterrupt = () => interrupt(130);
    const onTerminate = () => interrupt(143);
    process.on('SIGINT', onInterrupt);
    process.on('SIGTERM', onTerminate);
    const timer = setTimeout(() => interrupt(124), 50 * 60 * 1000);
    const cleanup = () => {
      clearTimeout(timer);
      process.removeListener('SIGINT', onInterrupt);
      process.removeListener('SIGTERM', onTerminate);
    };
    child.on('error', () => { cleanup(); resolveRun(interruptedExitCode ?? 127); });
    child.on('close', (code, signal) => {
      cleanup();
      const signals = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGABRT: 6, SIGKILL: 9, SIGTERM: 15 };
      resolveRun(interruptedExitCode ?? code ?? (signal === 'SIGKILL' ? 124 : 128 + (signals[signal] ?? 0)));
    });
  });
  return { exit_code: exitCode, log: boundedLog(Buffer.concat(chunks).toString('utf8'), truncated) };
}

function boundedLog(value, truncated = false) {
  if (Buffer.byteLength(value) > MAX_LOG || Buffer.byteLength(JSON.stringify(value)) > MAX_LOG) truncated = true;
  if (!truncated) return value;
  const suffix = '\n[Log truncated at 8 MiB]\n';
  let log = Buffer.from(value).subarray(0, MAX_LOG - 128).toString('utf8');
  while (Buffer.byteLength(log + suffix) > MAX_LOG || Buffer.byteLength(JSON.stringify(log + suffix)) > MAX_LOG) {
    log = log.slice(0, Math.max(0,
      Math.floor(log.length * (MAX_LOG - 128) / Buffer.byteLength(JSON.stringify(log + suffix))) - 128));
  }
  return log + suffix;
}

export function preparationDiagnostic(error, phase, elapsed, environment = process.env) {
  const detail = {
    phase: ['download', 'extract', 'execute', 'metadata', 'cleanup'].includes(phase) ? phase : 'unknown',
    elapsed_seconds: Number.isFinite(elapsed) && elapsed >= 0 ? Math.round(elapsed) / 1000 : 0,
    name: ['Error', 'TypeError', 'RangeError', 'SyntaxError', 'AbortError', 'TimeoutError'].includes(error?.name)
      ? error.name : 'Error',
  };
  if (Number.isInteger(error?.code) && error.code >= 0 && error.code <= 255
      || /^(?:ENOENT|EACCES|EPERM|EEXIST|ENOTDIR|ENOSPC|EIO|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAGAIN|ERR_CHILD_PROCESS_STDIO_MAXBUFFER)$/.test(error?.code)) {
    detail.code = error.code;
  }
  if (/^SIG(?:TERM|KILL|ABRT|INT|SEGV|BUS|PIPE|HUP)$/.test(error?.signal)) detail.signal = error.signal;
  if (/^(?:dscl (?:list|create|delete)|launchctl (?:bootstrap|bootout|asuser)|security (?:create-keychain|default-keychain|set-keychain-settings|unlock-keychain)|mkdir|mv|chown|chmod|pkill|rm)$/.test(error?.stage)) {
    detail.stage = error.stage;
    if (typeof error.stderr === 'string') {
      let stderr = error.stderr.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
        .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
      for (const [name, value] of Object.entries(environment)) {
        if (/TOKEN|KEY|SECRET|PASSWORD/i.test(name) && typeof value === 'string' && value.length >= 4) {
          stderr = stderr.replaceAll(value, '[REDACTED]');
        }
      }
      detail.stderr = stderr.slice(0, 2048);
    }
  }
  return JSON.stringify(detail);
}

function cleanupDiagnostics(operations) {
  if (!Array.isArray(operations)) return '';
  return operations.slice(0, 8).map(operation => `Isolation cleanup ${operation.failed ? 'failed' : 'completed'}. ${
    preparationDiagnostic(operation, 'cleanup', operation.elapsed)}`).join('\n');
}

export async function captureIsolated(run, cleanup) {
  let outcome;
  let executionError;
  try { outcome = await run(); } catch (error) { executionError = error; }
  const started = performance.now();
  let operations;
  try { operations = await cleanup(); }
  catch (error) {
    operations = error.cleanupOperations;
    if (!outcome) executionError ??= error;
    else {
      outcome.exit_code = 125;
      outcome.log += `\nIsolation cleanup failed. ${preparationDiagnostic(error, 'cleanup', performance.now() - started)}\n`;
    }
  }
  if (executionError) {
    executionError.cleanupOperations = operations;
    throw executionError;
  }
  outcome.log = boundedLog(`${outcome.log}\n${cleanupDiagnostics(operations)}\n[Task timing] isolation cleanup: ${
    ((performance.now() - started) / 1000).toFixed(3)}s\n`);
  return outcome;
}

async function produceReport(task, publicRun, part) {
  const directory = join(process.env.RUNNER_TEMP, `task-${task.id}`);
  const source = join(directory, 'source');
  const metadataPath = join(directory, '.relay-output.json');
  const started = performance.now();
  let phase = 'download';
  let phaseStarted = started;
  const timings = [];
  const finishPhase = () => timings.push(`[Task timing] ${phase}: ${((performance.now() - phaseStarted) / 1000).toFixed(3)}s`);
  const nextPhase = name => {
    finishPhase();
    phase = name;
    phaseStarted = performance.now();
  };
  let outcome;
  try {
    await mkdir(source, { recursive: true, mode: 0o700 });
    const archive = join(directory, 'source.tar.gz');
    await downloadSource(task, archive);
    nextPhase('extract');
    await command('tar', ['-xzf', archive, '--strip-components=1', '-C', source], { env: childEnvironment(process.env) });
    await rm(archive);
    let trustedSiteScript;
    if (task.kind === 'site') {
      // Pull-request sources must not choose the host-side deployment program.
      const response = await api(`repos/${task.repository}/contents/.github/ci/site.sh?ref=main`, {
        headers: { Accept: 'application/vnd.github.raw+json' },
      });
      const script = await response.text();
      if (Buffer.byteLength(script) > 64 * 1024) throw new Error('Site runner is too large');
      trustedSiteScript = join(directory, 'trusted-site.sh');
      await writeFile(trustedSiteScript, script, { mode: 0o600 });
    }
    nextPhase('execute');
    outcome = await runScript(source, task.platform, task.scope, {
      kind: task.kind ?? 'checks', parameters: task.parameters, sha: task.sha, metadataPath, trustedSiteScript, part,
    });
    nextPhase('metadata');
    try {
      const metadata = await lstat(metadataPath);
      if (!metadata.isFile() || metadata.size > 64 * 1024) throw new Error('Invalid metadata');
      const outputs = JSON.parse(await readFile(metadataPath, 'utf8'));
      if (!outputs || typeof outputs !== 'object' || Array.isArray(outputs)) throw new Error('Invalid metadata');
      outcome.outputs = outputs;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        outcome.exit_code = 125;
        outcome.log += `\nTask metadata invalid. ${preparationDiagnostic(error, phase, performance.now() - phaseStarted)}\n`;
      }
    }
  } catch (error) {
    outcome = { exit_code: 125,
      log: `Task preparation failed. ${preparationDiagnostic(error, phase, performance.now() - phaseStarted)}\n${
        cleanupDiagnostics(error.cleanupOperations)}\n` };
  }
  nextPhase('cleanup');
  try {
    await rm(directory, { recursive: true, force: true });
  } catch (error) {
    outcome.exit_code = 125;
    outcome.log += `Task cleanup failed. ${preparationDiagnostic(error, phase, performance.now() - phaseStarted)}\n`;
  }
  finishPhase();
  outcome.log += `\n${timings.join('\n')}\n[Task timing] total: ${((performance.now() - started) / 1000).toFixed(3)}s\n`;
  const report = buildReport(task, outcome, publicRun);
  report.log = boundedLog(report.log);
  return report;
}

async function storeResult(name, result) {
  const resultDirectory = join(process.env.RUNNER_TEMP, 'result');
  await mkdir(resultDirectory, { recursive: true, mode: 0o700 });
  await writeFile(join(resultDirectory, name), result, { mode: 0o600 });
}

async function execute() {
  const report = await produceReport(taskFromEnvironment(), runFromEnvironment());
  await storeResult('payload.bin', sealResult(report, process.env.CI_RESULT_PUBLIC_KEY, process.env.CI_RELAY_KEY));
}

async function executePart() {
  const task = taskFromEnvironment();
  validatePartTask(task);
  if (!['0', '1', '2'].includes(process.env.TASK_PART)) throw new Error('Invalid execution part');
  const part = Number(process.env.TASK_PART);
  const report = await produceReport(task, runFromEnvironment(), part);
  await storeResult('part.bin', sealPart(part, report, process.env.CI_RELAY_KEY));
}

async function combine() {
  const task = taskFromEnvironment();
  validatePartTask(task);
  const publicRun = runFromEnvironment();
  let report;
  try {
    const parts = await Promise.all([0, 1, 2].map(async part => {
      const file = join(process.env.RUNNER_TEMP, 'parts', `part-${part}`, 'part.bin');
      const metadata = await lstat(file);
      if (!metadata.isFile() || metadata.size > MAX_REPORT) throw new Error('Invalid part file');
      return openPart(await readFile(file), process.env.CI_RELAY_KEY, task, publicRun, part);
    }));
    report = combinePartReports(parts, task, publicRun);
  } catch {
    report = buildReport(task, { exit_code: 125, log: 'Partitioned task results missing or invalid.\n' }, publicRun);
  }
  await storeResult('payload.bin', sealResult(report, process.env.CI_RESULT_PUBLIC_KEY, process.env.CI_RELAY_KEY));
}

export async function cleanupParts() {
  const repository = process.env.GITHUB_REPOSITORY;
  const run = process.env.GITHUB_RUN_ID;
  const token = process.env.GITHUB_TOKEN;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '')
      || repository.split('/').some(name => name === '.' || name === '..')
      || !/^[1-9][0-9]{0,19}$/.test(run ?? '') || !token) throw new Error('Invalid cleanup context');
  const ids = [];
  for (let page = 1; ; page++) {
    const response = await api(`repos/${repository}/actions/runs/${run}/artifacts?per_page=100&page=${page}`, {}, token);
    const { artifacts } = await response.json();
    if (!Array.isArray(artifacts)) throw new Error('Invalid artifacts');
    for (const artifact of artifacts) {
      if (!['part-0', 'part-1', 'part-2'].includes(artifact.name)) continue;
      if (!Number.isSafeInteger(artifact.id) || artifact.id < 1) throw new Error('Invalid artifact id');
      ids.push(artifact.id);
    }
    if (artifacts.length < 100) break;
  }
  for (const id of ids) await api(`repos/${repository}/actions/artifacts/${id}`, { method: 'DELETE' }, token);
}

export async function callback() {
  const task = taskFromEnvironment();
  const { public_run_id: runId, public_run_attempt: attempt } = runFromEnvironment();
  await api(`repos/${task.repository}/dispatches`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event_type: 'ci-relay-result', client_payload: {
      run_id: runId, run_attempt: attempt, id: task.id, request_run_id: task.request_run_id,
      request_run_attempt: task.request_run_attempt, kind: task.kind ?? 'checks', platform: task.platform,
    } }),
  }, process.env.CI_CALLBACK_TOKEN);
}

function runFromEnvironment() {
  const public_run_id = process.env.GITHUB_RUN_ID;
  const public_run_attempt = process.env.GITHUB_RUN_ATTEMPT;
  if (!/^[1-9][0-9]{0,19}$/.test(public_run_id ?? '')
      || !/^[1-9][0-9]{0,5}$/.test(public_run_attempt ?? '')) throw new Error('Invalid run');
  return { public_run_id, public_run_attempt };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv[2] === 'execute') await execute();
    else if (process.argv[2] === 'execute-part') await executePart();
    else if (process.argv[2] === 'combine') await combine();
    else if (process.argv[2] === 'cleanup-parts') await cleanupParts();
    else if (process.argv[2] === 'callback') await callback();
    else throw new Error('Invalid operation');
  } catch {
    process.stderr.write('Task operation failed.\n');
    process.exitCode = 1;
  }
}
