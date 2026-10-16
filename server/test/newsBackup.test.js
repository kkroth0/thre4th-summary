import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { writeNewsBackupAtomic } from '../newsBackup.js';

function fixture(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatsumm4ry-news-backup-'));
    t.after(() => {
        assert.ok(path.resolve(directory).startsWith(path.resolve(os.tmpdir()) + path.sep + 'threatsumm4ry-news-backup-'));
        fs.rmSync(directory, { recursive: true, force: true });
    });
    return path.join(directory, 'archive.json');
}

test('large news backup retains every Unicode/IOC value and uses bounded writes including partial OS writes', t => {
    const file = fixture(t), rows = Array.from({ length: 100 }, (_, i) => ({ link: `https://lab.example/${i}`, title: 'Análise 🚀', text: 'Conteúdo'.repeat(4000), iocs: { hashes: ['a'.repeat(64)] }, optional: undefined }));
    let largest = 0, writes = 0;
    writeNewsBackupAtomic(file, rows, { ...fs, writeSync(fd, buffer, offset, length) {
        writes++; largest = Math.max(largest, buffer.length);
        return fs.writeSync(fd, buffer, offset, Math.min(length, 4096));
    } });
    assert.ok(writes > 100); assert.ok(largest < 350000);
    assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), JSON.parse(JSON.stringify(rows)));
    writeNewsBackupAtomic(file, []); assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), []);
});

test('backup serialization/disk/rename failure retains the last valid file and removes only its own temporary file', t => {
    const file = fixture(t), original = [{ title: 'previous good evidence' }];
    writeNewsBackupAtomic(file, original);
    const circular = {}; circular.self = circular;
    for (const [rows, io] of [[[circular], fs], [[{ value: 'x'.repeat(300000) }], { ...fs, writeSync() { throw Error('disk full'); } }], [[{ title: 'changed' }], { ...fs, renameSync() { throw Error('rename failed'); } }]]) {
        assert.throws(() => writeNewsBackupAtomic(file, rows, io));
        assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), original);
        assert.deepEqual(fs.readdirSync(path.dirname(file)), ['archive.json']);
    }
});
