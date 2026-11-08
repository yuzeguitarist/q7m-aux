import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { basename } from 'node:path';
import { promisify } from 'node:util';

const exec = promisify(execFile);

// A separate, non-admin UID is required: environment filtering alone does not
// stop a same-user process reading its privileged parent's process arguments.
export async function isolateMac(source, environment) {
  if (process.platform !== 'darwin') throw new Error('macOS isolation requires a macOS host');
  const user = `cfci${randomBytes(6).toString('hex')}`;
  const home = `/Users/${user}`;
  const stage = (file, args) => {
    const name = basename(file);
    const verb = name === 'dscl' ? args[1].replace(/^-/, '')
      : ['launchctl', 'security'].includes(name) ? args[0] : '';
    return name + (verb ? ` ${verb}` : '');
  };
  const run = async (file, args, label = stage(file, args)) => {
    try {
      return await exec(file, args, { env: environment, timeout: 30_000, maxBuffer: 1024 * 1024 });
    } catch (error) {
      error.stage = label;
      throw error;
    }
  };
  const root = (file, args) => run('/usr/bin/sudo', ['-n', file, ...args], stage(file, args));
  const users = await run('/usr/bin/dscl', ['.', '-list', '/Users', 'UniqueID']);
  const used = new Set(users.stdout.trim().split('\n').map(line => Number(line.trim().split(/\s+/).at(-1))));
  const uid = Array.from({ length: 1000 }, (_, i) => 60000 + i).find(id => !used.has(id));
  if (!uid) throw new Error('No isolated user id is available');
  let created = false;
  let bootstrapped = false;
  const cleanup = async () => {
    const operations = [];
    if (!created) return operations;
    const step = async (file, commandArgs, required = false) => {
      const started = performance.now();
      try {
        await root(file, commandArgs);
        operations.push({ stage: stage(file, commandArgs), elapsed: performance.now() - started, failed: false });
      } catch (error) {
        operations.push({ stage: error.stage, name: error.name, code: error.code,
          signal: error.signal, stderr: error.stderr, elapsed: performance.now() - started, failed: true });
        if (required) {
          error.cleanupOperations = operations;
          throw error;
        }
      }
    };
    await step('/usr/bin/pkill', ['-KILL', '-u', String(uid)]);
    if (bootstrapped) await step('/bin/launchctl', ['bootout', `user/${uid}`]);
    await step('/usr/bin/pkill', ['-KILL', '-u', String(uid)]);
    await step('/usr/bin/dscl', ['.', '-delete', `/Users/${user}`]);
    await step('/bin/rm', ['-rf', home], true);
    return operations;
  };
  const args = [
    '-n', '/bin/launchctl', 'asuser', String(uid), '/usr/bin/sudo', '-n', '-u', user,
    '/usr/bin/env', '-i', `HOME=${home}`, `USER=${user}`, `LOGNAME=${user}`,
    'PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin', 'CI=true',
  ];
  try {
    await root('/usr/bin/dscl', ['.', '-create', `/Users/${user}`]);
    created = true;
    for (const [field, value] of Object.entries({
      UniqueID: String(uid), PrimaryGroupID: '20', NFSHomeDirectory: home, UserShell: '/bin/bash', IsHidden: '1',
    })) await root('/usr/bin/dscl', ['.', '-create', `/Users/${user}`, field, value]);
    await root('/bin/mkdir', ['-p', `${home}/Library/Keychains`]);
    await root('/bin/mv', [source, `${home}/source`]);
    await root('/usr/sbin/chown', ['-RP', `${uid}:20`, home]);
    await root('/bin/chmod', ['700', home]);
    await root('/bin/launchctl', ['bootstrap', `user/${uid}`]);
    bootstrapped = true;
    const asUser = (file, commandArgs) => run('/usr/bin/sudo', [...args, file, ...commandArgs], stage(file, commandArgs));
    const keychain = `${home}/Library/Keychains/login.keychain-db`;
    await asUser('/usr/bin/security', ['create-keychain', '-p', '', keychain]);
    await asUser('/usr/bin/security', ['default-keychain', '-d', 'user', '-s', keychain]);
    await asUser('/usr/bin/security', ['set-keychain-settings', '-lut', '7200', keychain]);
    await asUser('/usr/bin/security', ['unlock-keychain', '-p', '', keychain]);
    return { source: `${home}/source`, args, stop: () => root('/usr/bin/pkill', ['-KILL', '-u', String(uid)]), cleanup };
  } catch (error) {
    try { error.cleanupOperations = await cleanup(); }
    catch (cleanupError) { error.cleanupOperations = cleanupError.cleanupOperations; }
    throw error;
  }
}
