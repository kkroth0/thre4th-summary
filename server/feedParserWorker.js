import { parentPort } from 'node:worker_threads';
import { parseFeed } from './feedParse.js';
parentPort.on('message', ({ id, args }) => {
  try { parentPort.postMessage({ id, items: parseFeed(...args) }); }
  catch { parentPort.postMessage({ id, error: 'Não foi possível interpretar o feed; cache anterior preservado.' }); }
});
