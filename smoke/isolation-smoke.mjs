import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { access, chmod, copyFile, mkdir, mkdtemp, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const canary = 'ISOLATION_SMOKE_PARENT_CANARY=synthetic-public-fixture-not-a-secret';
const exists = path => access(path).then(() => true, () => false);
const run = async (file, args) => (await execute(file, args, { timeout: 240_000, maxBuffer: 2 * 1024 * 1024 })).stdout;
const platform = process.platform === 'darwin' ? 'macos' : 'linux';
const moduleRoot = resolve(process.argv[2] ?? '.');

async function worker(configFile, mode) {
  const config = JSON.parse(await readFile(configFile, 'utf8'));
  config.mode = mode;
  config.parentPid = process.pid;
  const parent = platform === 'linux' ? join(dirname(configFile), `fixture-${mode}`)
    : await mkdtemp(join(tmpdir(), 'isolation-fixture-'));
  const source = join(parent, 'source');
  if (platform === 'linux') config.readyPath = '/workspace/checkpoint.json';
  await mkdir(join(source, '.github/ci'), { recursive: true });
  await copyFile(join(here, 'fixture.sh'), join(source, '.github/ci/run.sh'));
  await copyFile(join(here, 'fixture-probe.py'), join(source, 'fixture-probe.py'));
  await copyFile(join(here, 'keychain-probe.swift'), join(source, 'keychain-probe.swift'));
  await writeFile(join(source, 'fixture-config.json'), JSON.stringify(config));
  const { runScript } = await import(pathToFileURL(join(moduleRoot, 'relay.mjs')));
  try {
    const result = await runScript(source, platform, platform === 'macos' ? 'app' : 'source');
    process.stdout.write(JSON.stringify(result));
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
}

async function collectWorker(configFile, mode, readyPath) {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), moduleRoot, '--worker', configFile, mode], {
    env: { ...process.env, CI_RELAY_KEY: 'synthetic-not-a-key', CI_SOURCE_READ_TOKEN: 'synthetic-not-a-token',
      CI_CALLBACK_TOKEN: 'synthetic-not-a-token' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '', errors = '';
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { errors += data; });
  const finished = new Promise((resolveExit, reject) => {
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolveExit() : reject(new Error(`worker exited ${code}; stderr bytes=${errors.length}`)));
  });
  finished.catch(() => {}); // Readiness polling must still reach the cleanup path on early failure.
  if (mode === 'hold') {
    const deadline = Date.now() + 12 * 60_000;
    while (!await exists(readyPath)) {
      if (child.exitCode !== null || Date.now() > deadline) {
        child.kill('SIGTERM');
        await finished.catch(() => {});
        throw new Error('fixture never reached cancellation checkpoint');
      }
      await new Promise(resolveWait => setTimeout(resolveWait, 200));
    }
    child.kill('SIGTERM');
  }
  await finished;
  const outcome = JSON.parse(output);
  assert.equal(outcome.exit_code, { success: 0, failure: 17, hold: 143 }[mode]);
  const line = outcome.log.split('\n').find(value => value.startsWith('SMOKE_JSON:'));
  assert.ok(line, 'fixture must finish its assertions before teardown');
  return JSON.parse(line.slice('SMOKE_JSON:'.length));
}

async function main() {
  assert.equal(process.env.GITHUB_ACTIONS, 'true', 'run only in the disposable hosted smoke job');
  assert.equal(process.env.ISOLATION_SMOKE_PARENT_CANARY, 'synthetic-public-fixture-not-a-secret');
  assert.ok(Number(process.versions.node.split('.')[0]) >= 22);
  const parentEnvironment = platform === 'macos'
    ? await run('/bin/ps', ['eww', '-p', String(process.pid)])
    : (await readFile(`/proc/${process.pid}/environ`)).toString();
  assert.ok(parentEnvironment.includes(canary), 'same-UID positive control must see the synthetic parent canary');
  const root = await mkdtemp(join(tmpdir(), 'isolation-control-'));
  await chmod(root, 0o700);
  const readyRoot = await mkdtemp(join(tmpdir(), 'isolation-ready-'));
  await chmod(readyRoot, 0o733);
  const config = { hostUid: process.getuid(), hostHome: homedir(), hostCanary: join(root, 'host-canary') };
  await writeFile(config.hostCanary, 'synthetic-value-not-a-secret', { mode: 0o600 });
  let hostSimulator;
  const result = { platform, cases: [], passed: false };
  try {
    if (platform === 'macos') {
      config.hostKeychain = join(root, 'host.keychain-db');
      await run('/usr/bin/security', ['create-keychain', '-p', 'synthetic-password', config.hostKeychain]);
      await run('/usr/bin/security', ['unlock-keychain', '-p', 'synthetic-password', config.hostKeychain]);
      await run('/usr/bin/security', ['add-generic-password', '-a', 'synthetic', '-s', 'smoke-host',
        '-w', 'synthetic-value-not-a-secret', config.hostKeychain]);
      assert.equal((await run('/usr/bin/security', ['find-generic-password', '-a', 'synthetic', '-s', 'smoke-host',
        '-w', config.hostKeychain])).trim(), 'synthetic-value-not-a-secret');
      const runtimes = JSON.parse(await run('/usr/bin/xcrun', ['simctl', 'list', 'runtimes', '--json'])).runtimes
        .filter(row => row.isAvailable && row.name.startsWith('iOS ') && Number(row.version.split('.')[0]) >= 26)
        .sort((a, b) => a.version.localeCompare(b.version, undefined, { numeric: true }));
      const types = (runtimes.at(-1)?.supportedDeviceTypes ?? []).filter(row => row.name.startsWith('iPhone'));
      assert.ok(runtimes.length && types.length, 'an installed iOS simulator is required');
      config.simulatorRuntime = runtimes.at(-1).identifier;
      config.simulatorType = types.at(-1).identifier;
      hostSimulator = (await run('/usr/bin/xcrun', ['simctl', 'create', 'Isolation host fixture',
        config.simulatorType, config.simulatorRuntime])).trim();
      config.hostSimulator = hostSimulator;
    } else {
      config.hostPidNamespace = await readlink('/proc/self/ns/pid');
      config.hostMountNamespace = await readlink('/proc/self/ns/mnt');
    }
    for (const mode of ['success', 'failure', 'hold']) {
      config.readyPath = join(readyRoot, `${mode}.json`);
      const configFile = join(root, `${mode}.json`);
      await writeFile(configFile, JSON.stringify(config), { mode: 0o600 });
      const before = platform === 'linux' ? (await run('docker', ['ps', '-aq'])).trim().split('\n').filter(Boolean) : [];
      const checkpoint = platform === 'linux' ? join(root, `fixture-${mode}`, 'source/checkpoint.json') : config.readyPath;
      const observed = await collectWorker(configFile, mode, checkpoint);
      if (platform === 'macos') {
        assert.notEqual(observed.uid, config.hostUid);
        assert.equal(await exists(observed.home), false, 'isolated home must be deleted');
        const account = observed.home.split('/').at(-1);
        await assert.rejects(run('/usr/bin/dscl', ['.', '-read', `/Users/${account}`]));
        await assert.rejects(run('/usr/bin/sudo', ['-n', '/bin/launchctl', 'print', `user/${observed.uid}`]));
        assert.equal((await run('/bin/ps', ['-axo', 'uid='])).trim().split(/\s+/).includes(String(observed.uid)), false,
          'no process may survive under the isolated UID');
        if (observed.simulator) {
          const devices = await run('/usr/bin/xcrun', ['simctl', 'list', 'devices', '--json']);
          assert.equal(devices.includes(observed.simulator), false, 'child simulator must never appear in host device set');
        }
      } else {
        const after = (await run('docker', ['ps', '-aq'])).trim().split('\n').filter(Boolean);
        assert.deepEqual(after.filter(id => !before.includes(id)), [], 'no fixture container may survive');
      }
      result.cases.push({ mode, checks: observed.checks, cleanup: true });
      console.log(`PASS ${platform} ${mode}: isolation and teardown`);
    }
    result.passed = true;
  } finally {
    if (hostSimulator) await run('/usr/bin/xcrun', ['simctl', 'delete', hostSimulator]).catch(() => {});
    if (config.hostKeychain) await run('/usr/bin/security', ['delete-keychain', config.hostKeychain]).catch(() => {});
    await rm(root, { recursive: true, force: true });
    await rm(readyRoot, { recursive: true, force: true });
    await writeFile(join(process.env.RUNNER_TEMP, 'isolation-smoke-result.json'), JSON.stringify(result, null, 2));
  }
}

try {
  if (process.argv[3] === '--worker') await worker(process.argv[4], process.argv[5]);
  else await main();
} catch (error) {
  console.error(`Isolation smoke failed: ${error.message}`);
  process.exitCode = 1;
}
