import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createFeedCache } from '../feedCollector.js';
import { createNewsExportSourceReader } from '../newsExportSourceReader.js';

test('concurrent source exports share worker metadata and never return a partial build', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'news-export-reader-'));
    try {
        const cache = createFeedCache({ directory, fs, writeJsonAtomic: (file, data) => fs.writeFileSync(file, JSON.stringify(data)) });
        cache.set('enabled', { items: [{ title: 'Security vulnerability', link: 'https://example.test/a', pubDate: '2026-11-25T12:00:00Z', text: 'Original security report' }] });
        const read = createNewsExportSourceReader(directory);
        const first = read([{ url: 'enabled' }]);
        const second = read([{ url: 'enabled' }]);
        assert.equal(first, second);
        const rows = await first;
        assert.equal(rows.length, 1);
        assert.equal(rows[0].analysisStatus, 'Análise pendente');
        assert.equal(rows[0].text, undefined);
        assert.equal(await read([{ url: 'enabled' }]), rows);
        assert.deepEqual(await read([]), []);
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});
