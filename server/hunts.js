import crypto from 'node:crypto';

export const HUNTS_CAP = 200;

const CONTROL_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
const TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;
const CVE = /^CVE-\d{4}-\d{4,}$/;
const STATUSES = new Set(['draft', 'ready', 'archived']);

const clean = (value, max) => String(value ?? '').replace(CONTROL_CHARS, ' ').trim().slice(0, max);
const cleanList = (value, maxItems = 100) => [...new Set(
    (Array.isArray(value) ? value : []).map((item) => clean(item, 160)).filter(Boolean),
)].slice(0, maxItems);

/** Valida a entrada não confiável e fixa os campos de identidade no servidor. */
export function normalizeHuntInput(input = {}, {
    ownerSub,
    id = crypto.randomBytes(6).toString('hex'),
    createdAt,
    now = new Date().toISOString(),
} = {}) {
    if (!ownerSub) throw new Error('dono obrigatório');

    const title = clean(input.title, 300).replace(/\s+/g, ' ');
    const hypothesis = clean(input.hypothesis, 10000);
    if (!title) throw new Error('título obrigatório');
    if (!hypothesis) throw new Error('hipótese obrigatória');

    const techniques = cleanList(input.techniques).map((value) => value.toUpperCase());
    const cves = cleanList(input.cves).map((value) => value.toUpperCase());
    if (techniques.some((value) => !TECHNIQUE.test(value))) throw new Error('técnica inválida');
    if (cves.some((value) => !CVE.test(value))) throw new Error('CVE inválido');

    const status = clean(input.status || 'draft', 20).toLowerCase();
    if (!STATUSES.has(status)) throw new Error('status inválido');

    return {
        id,
        ownerSub,
        title,
        hypothesis,
        tactics: cleanList(input.tactics, 20),
        techniques: [...new Set(techniques)],
        cves: [...new Set(cves)],
        technologies: cleanList(input.technologies, 50),
        dataSources: cleanList(input.dataSources, 50),
        query: clean(input.query, 100000),
        queryLang: 'kql',
        notes: clean(input.notes, 10000),
        falsePositives: clean(input.falsePositives, 10000),
        status,
        sourceReportId: clean(input.sourceReportId, 80),
        hearthId: clean(input.hearthId, 40),
        createdAt: createdAt || now,
        updatedAt: now,
    };
}

/** Insere/atualiza no topo e corta o excedente mais antigo. */
export function upsertHunt(list = [], hunt, cap = HUNTS_CAP) {
    return [hunt, ...list.filter((item) => item.id !== hunt.id)].slice(0, cap);
}
