import { fileURLToPath } from 'node:url';
import { captureCommand, childEnvironment } from '../relay.mjs';

const source = fileURLToPath(new URL('./source', import.meta.url));
const result = await captureCommand('bash', [`${source}/.github/ci/run.sh`, 'linux'], source,
  { ...childEnvironment(process.env), CI_SCOPE: 'source', WAIT_MARKER: process.argv[2] });
process.stdout.write(JSON.stringify({
  result, interruptListeners: process.listenerCount('SIGINT'), terminateListeners: process.listenerCount('SIGTERM'),
}));
