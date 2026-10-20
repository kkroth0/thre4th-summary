import axios from 'axios';
import { writeFileSync } from 'node:fs';
import { HUNTING_SOURCES, collectHuntingRepository, mergeHuntingQueries } from '../huntingLibrary.js';

const sources = [], queries = [];
for (const source of HUNTING_SOURCES) {
  const { queries: rows, ...metadata } = await collectHuntingRepository(source, axios, process.env.GITHUB_TOKEN || '');
  sources.push(metadata); queries.push(...rows);
  console.log(source.repo, rows.length, metadata.revision);
}
const snapshot = { updatedAt: new Date().toISOString(), sources, queries: mergeHuntingQueries(queries) };
writeFileSync(new URL('../data/hunting-library.json', import.meta.url), JSON.stringify(snapshot));
console.log('Unique queries:', snapshot.queries.length);
