// Offline input: { brands: [...], samples: [{ hostname, firstSeen, cohort,
// label: 'malicious'|'legitimate', certificates: [raw crt.sh records] }] }.
import fs from 'node:fs';
import { evaluateCtBacktest } from './phishingCtBacktest.js';
const file = process.argv[2];
if (!file) { console.error('Usage: node server/backtestPhishingCt.mjs input.json'); process.exitCode = 1; }
else {
  const input = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!Array.isArray(input.samples) || input.samples.length > 5000 || !Array.isArray(input.brands) || input.brands.length > 100) throw Error('Invalid or oversized backtest input');
  console.log(JSON.stringify(evaluateCtBacktest(input.samples, { brands: input.brands }), null, 2));
}
