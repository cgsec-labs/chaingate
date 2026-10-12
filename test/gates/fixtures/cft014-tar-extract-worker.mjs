// 0.1.4 release audit (G4 dated note 6): extracts one archive with a given node-tar under pacote's options, in a worker
// thread, so an error node-tar throws from a callback (npm's install would fail on that archive) ends this worker, not the
// test. The parent creates and removes the folders.
import fs from 'node:fs';
import path from 'node:path';
import { parentPort, workerData } from 'node:worker_threads';

const tar = await import(workerData.tarUrl);
parentPort.on('message', async ({ id, file, dest }) => {
  try {
    await tar.x({ file, cwd: dest, strip: 1, noChmod: true, noMtime: true, onwarn: () => {},
      filter: (n, e) => { if (/Link$/.test(e.type)) return false; if (/File$/.test(e.type)) return true; return undefined; } });
    const pj = path.join(dest, 'package.json');
    parentPort.postMessage({ id, pj: fs.existsSync(pj) && fs.lstatSync(pj).isFile() ? fs.readFileSync(pj, 'utf8') : null });
  } catch (err) { parentPort.postMessage({ id, error: String(err.code ?? err.message).slice(0, 60) }); }
});
