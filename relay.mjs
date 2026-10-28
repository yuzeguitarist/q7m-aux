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
  const { kind = 'checks', parameters = {}, sha, metadataPath, trustedSiteScript } = options;
  validateParameters(parameters);
  if (kind === 'site' && !trustedSiteScript) throw new Error('Site tasks require a trusted runner script');
  const script = kind === 'site' ? trustedSiteScript : join(source, '.github/ci/run.sh');
  const canonicalSource = await realpath(source);
  const canonicalScript = await realpath(script);
  if (!(await lstat(script)).isFile()
      || (kind !== 'site' && !canonicalScript.startsWith(canonicalSource + sep))) {
    throw new Error('Invalid script');
  }
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
  try {
    return await captureCommand('/usr/bin/sudo', [...isolated.args,
      `CI_SCOPE=${scope}`, '/bin/bash', `${isolated.source}/.github/ci/run.sh`, platform,
    ], '/', childEnvironment(process.env), isolated.stop);
  } finally { await isolated.cleanup(); }
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
  let log = Buffer.concat(chunks).toString('utf8');
  if (Buffer.byteLength(log) > MAX_LOG) {
    log = Buffer.from(log).subarray(0, MAX_LOG).toString('utf8');
    truncated = true;
  }
  while (Buffer.byteLength(JSON.stringify(log)) > MAX_LOG) {
    log = log.slice(0, Math.max(0, Math.floor(log.length * MAX_LOG / Buffer.byteLength(JSON.stringify(log))) - 128));
    truncated = true;
  }
  return { exit_code: exitCode, log: log + (truncated ? '\n[Log truncated at 8 MiB]\n' : '') };
}

async function execute() {
  const task = taskFromEnvironment();
  const publicRun = runFromEnvironment();
  const directory = join(process.env.RUNNER_TEMP, `task-${task.id}`);
  const source = join(directory, 'source');
  const metadataPath = join(directory, '.relay-output.json');
  await mkdir(source, { recursive: true, mode: 0o700 });
  let outcome;
  try {
    const archive = join(directory, 'source.tar.gz');
    await downloadSource(task, archive);
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
    outcome = await runScript(source, task.platform, task.scope, {
      kind: task.kind ?? 'checks', parameters: task.parameters, sha: task.sha, metadataPath, trustedSiteScript,
    });
    try {
      const metadata = await lstat(metadataPath);
      if (!metadata.isFile() || metadata.size > 64 * 1024) throw new Error('Invalid metadata');
      const outputs = JSON.parse(await readFile(metadataPath, 'utf8'));
      if (!outputs || typeof outputs !== 'object' || Array.isArray(outputs)) throw new Error('Invalid metadata');
      outcome.outputs = outputs;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        outcome.exit_code = 125;
        outcome.log += '\nTask metadata invalid.\n';
      }
    }
  } catch {
    outcome = { exit_code: 125, log: 'Task preparation failed.\n' };
  }
  const report = buildReport(task, outcome, publicRun);
  const result = sealResult(report, process.env.CI_RESULT_PUBLIC_KEY, process.env.CI_RELAY_KEY);
  const resultDirectory = join(process.env.RUNNER_TEMP, 'result');
  await mkdir(resultDirectory, { recursive: true, mode: 0o700 });
  await writeFile(join(resultDirectory, 'payload.bin'), result, { mode: 0o600 });
  await rm(directory, { recursive: true, force: true });
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
    else if (process.argv[2] === 'callback') await callback();
    else throw new Error('Invalid operation');
  } catch {
    process.stderr.write('Task operation failed.\n');
    process.exitCode = 1;
  }
}
