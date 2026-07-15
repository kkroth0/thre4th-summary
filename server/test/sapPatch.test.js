import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
    parseSapNotes, latestPatchMonth, monthUrl, summarize, sortNotes, PRIORITY_RANK,
} from '../sapPatch.js';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, 'fixtures', 'sap-july-2026.html'), 'utf8');
const { releaseDate, notes } = parseSapNotes(html);

test('parseSapNotes extracts the month notes with their fields', () => {
    assert.ok(notes.length >= 15, `expected ~16 notes, got ${notes.length}`);
    assert.equal(releaseDate, '2026-07-14'); // second Tuesday of July 2026

    const hot = notes.find((n) => n.note === '3747367');
    assert.ok(hot, 'note 3747367 present');
    assert.equal(hot.noteUrl, 'https://me.sap.com/notes/3747367');
    assert.deepEqual(hot.cves, ['CVE-2026-44747']);
    assert.equal(hot.priority, 'Critical');
    assert.equal(hot.cvss, 9.9);
    assert.match(hot.cvssVector, /^CVSS:/);
    assert.equal(hot.isUpdate, false);
    assert.ok(!hot.title.startsWith('['), 'CVE prefix stripped from title');
});

test('parseSapNotes flags re-release rows and drops non-note rows', () => {
    const update = notes.find((n) => n.note === '3727078');
    assert.ok(update && update.isUpdate, 'note 3727078 flagged as update');
    // Every parsed row is a real SAP note number (header row excluded).
    assert.ok(notes.every((n) => /^\d{6,}$/.test(n.note)));
});

test('parseSapNotes never throws on junk input', () => {
    assert.deepEqual(parseSapNotes('<html><body>no table</body></html>').notes, []);
    assert.deepEqual(parseSapNotes('').notes, []);
});

test('latestPatchMonth picks current month on/after 2nd Tuesday, else previous', () => {
    // July 2026 Patch Day = 14 Jul. Before it -> June; on/after -> July.
    assert.equal(latestPatchMonth(new Date('2026-07-13T12:00:00Z')).monthName, 'june');
    assert.equal(latestPatchMonth(new Date('2026-07-14T12:00:00Z')).monthName, 'july');
    // January before patch day rolls back to December of the prior year.
    const jan = latestPatchMonth(new Date('2026-01-05T12:00:00Z'));
    assert.equal(jan.monthName, 'december');
    assert.equal(jan.year, 2025);
});

test('monthUrl builds the SAP security-notes-news URL', () => {
    assert.equal(monthUrl(2026, 6),
        'https://support.sap.com/en/my-support/knowledge-base/security-notes-news/july-2026.html');
});

test('summarize and sortNotes rank by priority then CVSS', () => {
    const s = summarize(notes);
    assert.equal(s.total, notes.length);
    assert.ok(s.hotNews >= 1 && s.maxCvss === 9.9 && s.cveCount >= 1);
    const sorted = sortNotes(notes);
    assert.ok((PRIORITY_RANK[sorted[0].priority] || 0) >= (PRIORITY_RANK[sorted.at(-1).priority] || 0));
});
