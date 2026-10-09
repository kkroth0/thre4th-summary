// Offline rebuild using exactly the same migration as the feed refresher.
// Stop the running service before --write; it holds a separate in-memory store.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rebuildStoryCorrelations, CORRELATION_VERSION } from './newsStories.js';

const args = process.argv.slice(2);
const write = args.includes('--write');
const file = args.find((arg) => !arg.startsWith('--')) || path.join(path.dirname(fileURLToPath(import.meta.url)), '.news-stories.json');
const stories = JSON.parse(fs.readFileSync(file, 'utf8'));
if (!Array.isArray(stories)) throw new Error('Expected a story array');

const rebuilt = rebuildStoryCorrelations(stories);
const multi = (list) => list.filter((story) => story.sources.length > 1).length;
console.log(JSON.stringify({ file, correlationVersion: CORRELATION_VERSION, before: { events: stories.length, multiSource: multi(stories) },
    after: { events: rebuilt.length, multiSource: multi(rebuilt) }, write }, null, 2));
if (write) {
    fs.copyFileSync(file, file + '.bak');
    const temp = file + '.rebuild.tmp';
    fs.writeFileSync(temp, JSON.stringify(rebuilt));
    fs.renameSync(temp, file);
    console.log('Saved; previous state preserved in ' + file + '.bak. Restart the service.');
} else {
    console.log('dry-run; no state was changed. The next feed refresh also migrates older correlation versions automatically.');
}
