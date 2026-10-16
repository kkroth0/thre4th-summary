import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { AI_TOOL_CATALOG, AI_CATEGORIES, classifyAiTool } from '../aiToolCatalog.js';
import { createAiPatchDay, mergeAiPatches, normalizeAiAdvisory, normalizeAiNvd } from '../aiPatchDay.js';
import { createVulnerabilityCatalog } from '../vulnerabilityCatalog.js';

const advisory = (extra = {}) => ({ ghsa_id: 'GHSA-abcd-1234-efgh', cve_id: 'CVE-2026-12345', summary: 'MCP tool command injection', description: 'A Model Context Protocol server has a command injection issue.', published_at: '2026-10-01T12:00:00Z', updated_at: '2026-10-02T12:00:00Z', html_url: 'https://github.com/advisories/GHSA-abcd-1234-efgh', references: ['https://github.com/new-vendor/new-mcp/security/advisories/GHSA-abcd-1234-efgh'], vulnerabilities: [{ package: { ecosystem: 'npm', name: '@new-vendor/unknown-mcp' }, vulnerable_version_range: '< 2.0.1', first_patched_version: '2.0.1' }], ...extra });
const local = () => ({ rows: [], status: { sources: Object.fromEntries(['nvd','kev','epss'].map(id => [id, { status: 'ready', at: '2026-10-16T10:00:00Z' }])) } });

test('AI coverage spans inference, agents, MCP, data, ML frameworks and coding assistants', () => {
    assert.ok(AI_TOOL_CATALOG.length > 100); assert.ok(AI_CATEGORIES.length >= 8);
    for (const name of ['Ollama','Open WebUI','LiteLLM','vLLM','LangChain','LlamaIndex','MLflow','Gradio','Transformers','MCP Python SDK','MCP TypeScript SDK','Claude Code','Codex CLI','Gemini CLI','Cline','CrewAI','Qdrant','PyTorch']) assert.ok(AI_TOOL_CATALOG.some(t => t.name === name), name);
    assert.equal(classifyAiTool({ packages: [{ name: '@modelcontextprotocol/sdk' }] })[0].category, 'MCP e integrações');
    assert.equal(classifyAiTool({ packages: [{ name: 'langchain_core' }] })[0].name, 'LangChain');
    assert.equal(classifyAiTool({ summary: 'Model Context Protocol server command injection', packages: [{ name: 'brand-new-package' }] })[0].evidence, 'discovery');
    assert.deepEqual(classifyAiTool({ text: 'Railway email contains a cursor and a jan calendar. MCP controller does not work.' }), []);
    assert.deepEqual(classifyAiTool({ text: 'Arbitrary file read in ordinary HTTP server', product: 'mailserver' }), []);
    assert.deepEqual(classifyAiTool({ packages: [{ name: 'ordinary-http-server' }], summary: 'Server bug', text: 'Continue processing requests. Reported by Claude. Transformers deliver power to the facility.' }), []);
    const plugin = classifyAiTool({ text: 'The S2B AI Assistant – ChatBot, ChatGPT, OpenAI plugin for WordPress is vulnerable to arbitrary uploads.' });
    assert.equal(plugin[0].name, 'S2B AI Assistant – ChatBot, ChatGPT, OpenAI plugin for WordPress');
    assert.equal(plugin[0].evidence, 'discovery'); assert.notEqual(plugin[0].name, 'ChatGPT');
    assert.deepEqual(classifyAiTool({ text: 'Ordinary HTTP Server is vulnerable to file disclosure. Reported by ChatGPT.' }), []);
});

test('GHSA preserves exact affected and fixed versions; CVE presence alone never confirms a patch', () => {
    const row = normalizeAiAdvisory(advisory());
    assert.equal(row.patch, 'available'); assert.equal(row.categories[0], 'MCP e integrações');
    assert.ok(row.products.some(p => p.status === 'fixed' && p.name.includes('2.0.1')));
    assert.ok(row.products.some(p => p.status === 'affected' && p.name.includes('< 2.0.1')));
    const unconfirmed = normalizeAiAdvisory(advisory({ vulnerabilities: [{ package: { name: 'langchain' }, vulnerable_version_range: '*' }] }));
    assert.equal(unconfirmed.patch, 'unconfirmed'); assert.equal(unconfirmed.remediations.length, 0);
    assert.equal(normalizeAiAdvisory(advisory({ withdrawn_at: '2026-10-03' })), null);
    assert.equal(normalizeAiAdvisory(advisory({ type: 'unreviewed' })), null);
    assert.equal(normalizeAiAdvisory(advisory({ summary: 'Server bug', description: 'Ordinary web server', vulnerabilities: [{ package: { name: 'ordinary-http-server' } }] })), null);
});

test('CVE join deduplicates NVD evidence while preserving distinct GHSA/package advisories and zero EPSS', () => {
    const gh = normalizeAiAdvisory(advisory());
    const nvd = normalizeAiNvd({ id: 'CVE-2026-12345', tools: [{ name: 'MCP component', category: 'MCP e integrações' }], cvss: 9.8, epss: 0, kev: true, references: [], published: '2026-10-01', modified: '2026-10-03' });
    const rows = mergeAiPatches([gh], [nvd]);
    assert.equal(rows.length, 1); assert.equal(rows[0].kev, true); assert.equal(rows[0].cveSignals[0].epss, 0);
    assert.equal(rows[0].patch, 'available'); assert.equal(rows[0].cvss, 9.8);
    assert.equal(mergeAiPatches([gh, { ...gh, id: 'GHSA-aaaa-bbbb-cccc' }], [nvd]).length, 2);
    const time = normalizeAiNvd({ ...nvd, id: 'CVE-2026-55555', published: '2026-10-31T23:30:00.000', modified: '2026-10-31T23:59:00.000' });
    assert.equal(time.published, '2026-10-31T23:30:00.000Z'); assert.equal(time.updated, '2026-10-31T23:59:00.000Z');
});

test('global source uses bounded single-flight pages, durable cursor, no per-view calls, and retains cache on failure', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ai-patch-test-')), filePath = path.join(directory, 'cache.json');
    let clock = Date.parse('2026-10-16T12:00:00Z'), calls = 0, fail = false;
    const http = { get: async url => { calls++; const parsed = new URL(url), range = parsed.searchParams.get('modified'); if (range) { assert.match(range, /^\d{4}-\d\d-\d\d\.\.\d{4}-\d\d-\d\d$/); assert.equal(parsed.searchParams.get('type'), 'reviewed'); } if (fail) throw { response: { status: 429 } }; return { data: [advisory()], headers: { link: '<https://api.github.com/advisories?after=cursor>; rel="next"' } }; } };
    try {
        const day = createAiPatchDay({ filePath, http, queryCatalog: async () => local(), now: () => clock, pageBudget: 1 });
        await Promise.all([day.sync(), day.sync()]); assert.equal(calls, 1);
        const before = await day.query({ month: '2026-10' }); assert.equal(before.rows.length, 1); assert.equal(before.status.pending, 1);
        await day.query({ month: '2026-10' }); assert.equal(calls, 1);
        const restored = createAiPatchDay({ filePath, http, queryCatalog: async () => local(), now: () => clock, pageBudget: 1 });
        assert.equal((await restored.query({ month: '2026-10' })).rows[0].patch, 'available');
        clock += 3600001; fail = true; await restored.sync();
        const after = await restored.query({ month: '2026-10' }); assert.equal(after.rows.length, 1); assert.equal(after.sources[0].status, 'stale'); assert.equal(after.status.failed, 1);
        await assert.rejects(day.query({ month: '2026-13' }), /Invalid/);
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('pagination rejects redirects to arbitrary hosts and reports incomplete source honestly', async () => {
    let calls = 0;
    const day = createAiPatchDay({ now: () => Date.parse('2026-10-16'), queryCatalog: async () => { throw Error('locked'); }, http: { get: async () => { calls++; return { data: [advisory()], headers: { link: '<https://attacker.test/api>; rel="next"' } }; } } });
    await day.sync(); const data = await day.query({ month: '2026-10' });
    assert.equal(calls, 1); assert.equal(data.sources[0].status, 'stale'); assert.equal(data.sources[1].status, 'error'); assert.equal(data.status.initialized, false);
});

test('daily collection continues during backfill and an older historical row cannot undo a new fix', async () => {
    let clock = Date.parse('2026-10-16T12:00:00Z'), calls = 0;
    const addresses = [];
    const day = createAiPatchDay({ now: () => clock, queryCatalog: async () => local(), pageBudget: 2, http: { get: async url => {
        addresses.push(url);
        calls++;
        const fresh = calls === 3 ? advisory({ updated_at: '2026-10-17T10:00:00Z', vulnerabilities: [{ package: { name: 'mcp' }, first_patched_version: '2.0.2' }] }) : advisory();
        return { data: [fresh], headers: calls % 2 === 0 ? { link: '<https://api.github.com/advisories?after=history>; rel="next"' } : {} };
    } } });
    await day.sync(); assert.equal(calls, 2);
    assert.ok(new URL(addresses[1]).searchParams.get('affects').includes('@modelcontextprotocol/sdk'));
    assert.equal(new URL(addresses[1]).searchParams.get('type'), 'reviewed');
    clock += 86400001; await day.sync(); assert.equal(calls, 4);
    const result = await day.query({ month: '2026-10' });
    assert.equal(result.rows[0].updated, '2026-10-17T10:00:00Z');
    assert.ok(result.rows[0].products.some(p => p.status === 'fixed' && p.name.includes('2.0.2')));
    assert.equal(result.coverage.historicalImportPending, true);
});

test('local NVD query selects monthly AI CVEs and joined older GHSA CVEs without inventing fixes', () => {
    const catalog = createVulnerabilityCatalog({ years: [] });
    const cve = (id, description, published, modified = published) => ({ cve: { id, descriptions: [{ lang: 'en', value: description }], published, lastModified: modified, references: [] } });
    try {
        catalog.ingest([cve('CVE-2026-11111', 'Ollama allows denial of service', '2026-10-01T00:00:00'), cve('CVE-2026-22222', 'MCP server implements Model Context Protocol and allows command injection', '2026-01-01T00:00:00', '2026-10-02T00:00:00'), cve('CVE-2026-33333', 'Email service issue', '2026-10-01T00:00:00'), cve('CVE-2025-44444', 'Package without recognizable AI terms', '2025-01-01T00:00:00')]);
        const data = catalog.aiPatches({ month: '2026-10', ids: ['CVE-2025-44444'] });
        assert.deepEqual(data.rows.map(r => r.id), ['CVE-2025-44444','CVE-2026-11111','CVE-2026-22222']);
        assert.equal(normalizeAiNvd(data.rows[1]).patch, 'unconfirmed');
    } finally { catalog.close(); }
});
