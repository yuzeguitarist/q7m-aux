import { fileURLToPath } from 'node:url';
import { runScript } from '../relay.mjs';

const result = await runScript(fileURLToPath(new URL('./source', import.meta.url)), 'linux', 'source', {
  parameters: { WAIT_MARKER: process.argv[2] },
});
process.stdout.write(JSON.stringify({
  result, interruptListeners: process.listenerCount('SIGINT'), terminateListeners: process.listenerCount('SIGTERM'),
}));
