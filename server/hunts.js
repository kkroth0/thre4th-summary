import crypto from 'node:crypto';

export const HUNTS_CAP = 200;

const CONTROL_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
const TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;
const CVE = /^CVE-\d{4}-\d{4,}$/;
const STATUSES = new Set(['draft', 'ready', 'archived']);

// Execucao != conteudo. `status` diz se a hunt esta escrita; `runs` diz o que o
// analista fez com ela. Uma hunt mensal roda varias vezes, entao execucao e
// lista, nao campo — sem isso nao ha controle do mes.
export const RUN_STATES = ['pending', 'running', 'done'];
export const RUN_OUTCOMES = ['none', 'suspicious', 'incident'];
export const RUNS_CAP = 24; // dois anos de cadencia mensal por hunt

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
        runs: Array.isArray(input.runs) ? input.runs.slice(0, RUNS_CAP) : [],
        createdAt: createdAt || now,
        updatedAt: now,
    };
}

/**
 * Valida o registro de execucao. O formulario nao tem campo de cliente de
 * proposito: o que nao existe nao vaza. Sobra contagem (numero) e nota livre,
 * que passa pela mesma limpeza de controle do resto.
 */
export function normalizeRunInput(input = {}, {
    id = crypto.randomBytes(6).toString('hex'),
    startedAt,
    now = new Date().toISOString(),
} = {}) {
    const state = clean(input.state || 'pending', 20).toLowerCase();
    if (!RUN_STATES.includes(state)) throw new Error('estado de execução inválido');

    const outcome = clean(input.outcome || 'none', 20).toLowerCase();
    if (!RUN_OUTCOMES.includes(outcome)) throw new Error('resultado inválido');
    // Achado so existe em execucao fechada: marcar incidente numa hunt que nem
    // comecou e o tipo de registro que suja o controle do mes inteiro.
    if (state !== 'done' && outcome !== 'none') throw new Error('resultado só em execução finalizada');

    // Ausente e zero: o analista que so abriu a execucao nao preencheu contagem.
    const events = Number(input.events ?? 0);
    const hosts = Number(input.hosts ?? 0);
    if ([events, hosts].some((value) => !Number.isFinite(value) || value < 0 || value > 1e9)) {
        throw new Error('contagem inválida');
    }

    return {
        id,
        state,
        outcome,
        events: Math.trunc(events),
        hosts: Math.trunc(hosts),
        findings: clean(input.findings, 5000),
        startedAt: startedAt || now,
        finishedAt: state === 'done' ? now : null,
        updatedAt: now,
    };
}

/** Insere/atualiza a execucao no topo da hunt e corta o excedente. */
export function upsertRun(hunt, run, cap = RUNS_CAP) {
    const runs = [run, ...(Array.isArray(hunt.runs) ? hunt.runs : []).filter((item) => item.id !== run.id)];
    return { ...hunt, runs: runs.slice(0, cap), updatedAt: run.updatedAt };
}

/**
 * Resumo do mes pro painel: quantas hunts pararam em cada estado e o que
 * saiu delas. `month` no formato YYYY-MM; execucao entra pelo inicio, entao
 * hunt comecada em janeiro e fechada em fevereiro conta em janeiro.
 */
export function monthlySummary(list = [], month) {
    const runs = list.flatMap((hunt) => (hunt.runs || [])
        .filter((run) => String(run.startedAt || '').slice(0, 7) === month)
        .map((run) => ({ ...run, huntId: hunt.id, title: hunt.title })));

    const byState = Object.fromEntries(RUN_STATES.map((state) => [state, 0]));
    const byOutcome = Object.fromEntries(RUN_OUTCOMES.map((outcome) => [outcome, 0]));
    for (const run of runs) {
        byState[run.state] += 1;
        if (run.state === 'done') byOutcome[run.outcome] += 1;
    }

    return { month, total: runs.length, byState, byOutcome, runs };
}

/** Insere/atualiza no topo e corta o excedente mais antigo. */
export function upsertHunt(list = [], hunt, cap = HUNTS_CAP) {
    return [hunt, ...list.filter((item) => item.id !== hunt.id)].slice(0, cap);
}
