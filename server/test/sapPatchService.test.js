import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createSapPatchService } from '../sapPatchService.js';
import { parseSapNotes } from '../sapPatch.js';

const html = fs.readFileSync(new URL('./fixtures/sap-july-2026.html', import.meta.url), 'utf8');
const date = Date.parse('2026-10-16T12:00:00Z');
test('SAP monthly requests coalesce and survive restart without mixing periods', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sap-month-')), filePath = path.join(dir, 'cache.json');
    let calls = 0;
    const http = { get: async url => { calls++; assert.match(url, /july-2026.html$/); return { data: html }; } };
    try {
        const service = createSapPatchService({ http, now: () => date, filePath });
        const [a, b] = await Promise.all([service.query('2026-07'), service.query('2026-07')]);
        assert.equal(calls, 1); assert.equal(a.releaseDate, '2026-07-14'); assert.equal(a, b);
        const restart = createSapPatchService({ http, now: () => date, filePath });
        assert.equal((await restart.query('2026-07')).notes.length, a.notes.length); assert.equal(calls, 1);
        await assert.rejects(restart.query('2026-08'), e => e.status === 502);
        assert.equal(calls, 2);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('an unavailable SAP month cannot silently fall back to another month', async () => {
    const calls = [], service = createSapPatchService({ now: () => date, http: { get: async url => { calls.push(url); throw { response: { status: 404 } }; } } });
    await assert.rejects(service.query('2026-09'), e => e.status === 404);
    assert.equal(calls.length, 1); assert.match(calls[0], /september-2026/);
    for (const month of ['2026-13', '2026-11', '2017-12', ['2026-07'], '../private']) await assert.rejects(service.query(month), e => e.status === 400);
    assert.equal(calls.length, 1);
});
test('an expired SAP snapshot remains available with stale status during source failure', async () => {
    let time = date, fail = false;
    const service = createSapPatchService({ now: () => time, http: { get: async () => { if (fail) throw Error('offline'); return { data: html }; } } });
    const first = await service.query('2026-07'); time += 86400001; fail = true;
    const stale = await service.query('2026-07'); assert.equal(stale.stale, true); assert.deepEqual(stale.notes, first.notes);
});
test('SAP GitHub advisories retain their identity and safe source links', () => {
    const id = 'GHSA-abcd-1234-5678';
    const page = href => `<table><tr><th>Note#</th><th>Title</th><th>Priority</th><th>CVSS</th></tr><tr><td><a href="${href}">${id} (opens in new tab)</a></td><td>[CVE-2026-12345] CAP vulnerability</td><td>High</td><td>8.1</td></tr></table>`;
    for (const href of [`https://github.com/SAP/cap/advisories/${id}`, `https://evil.test/advisories/${id}`]) {
        const [note] = parseSapNotes(page(href)).notes;
        assert.equal(note.note, id); assert.deepEqual(note.cves, ['CVE-2026-12345']);
        assert.equal(note.noteUrl, href.startsWith('https://github.com/') ? href : `https://github.com/advisories/${id}`);
    }
});
