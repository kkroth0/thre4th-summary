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

// Cadencia: de quanto em quanto tempo a hunt deveria rodar. 'intel' e sob
// demanda (chega inteligencia, roda), entao nao vence.
export const CADENCES = { daily: 1, weekly: 7, monthly: 30, intel: 0 };

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
        // De qual catalogo a hunt foi adotada ('' = o analista escreveu). NAO
        // reusar o nome `origin`: no catalogo do HEARTH esse campo significa
        // "item de catalogo", e misturar os dois faz a hunt adotada ser tratada
        // como item publico — que foi exatamente o bug da tela branca.
        adoptedFrom: ['hearth', 'ptbr'].includes(clean(input.adoptedFrom, 20)) ? clean(input.adoptedFrom, 20) : '',
        sourceId: clean(input.sourceId, 200),
        cadence: Object.hasOwn(CADENCES, clean(input.cadence, 20)) ? clean(input.cadence, 20) : '',
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

/**
 * Hunts que ja deveriam ter rodado e nao rodaram. E a pergunta que o quadro nao
 * respondia: ele mostra o que foi feito, isto mostra o que ficou pra tras.
 * Sem cadencia a hunt nunca vence — quem nao definiu ritmo nao esta atrasado.
 */
export function overdueHunts(list = [], now = Date.now()) {
    return list
        .map((hunt) => {
            const days = CADENCES[hunt.cadence];
            if (!days) return null;

            // A ultima execucao que conta e a mais recente por inicio; a lista
            // guarda a mais nova no topo, mas nao da pra confiar nisso depois de
            // uma reabertura ter mexido na ordem.
            const last = (hunt.runs || [])
                .map((run) => Date.parse(run.startedAt))
                .filter(Number.isFinite)
                .sort((a, b) => b - a)[0];

            const dueMs = days * 24 * 60 * 60 * 1000;
            const elapsed = last === undefined ? Infinity : now - last;
            if (elapsed < dueMs) return null;

            return {
                id: hunt.id,
                title: hunt.title,
                cadence: hunt.cadence,
                lastRunAt: last === undefined ? null : new Date(last).toISOString(),
                daysLate: last === undefined ? null : Math.floor((elapsed - dueMs) / (24 * 60 * 60 * 1000)),
            };
        })
        .filter(Boolean)
        // Nunca rodou primeiro, depois o mais atrasado.
        .sort((a, b) => (a.lastRunAt === null ? -1 : b.lastRunAt === null ? 1 : b.daysLate - a.daysLate));
}

/**
 * Preenche os campos que nao existiam quando a hunt foi salva. O store e um
 * JSON flat sem migracao: sem isto, hunt de ontem chega no cliente sem `origin`
 * e sem `runs`, e quem indexa por esses campos quebra.
 */
export function withDefaults(hunt) {
    // `origin` foi usado por engano nas hunts privadas antes de virar
    // `adoptedFrom`. Some daqui: enquanto ele existir no payload, a tela trata
    // hunt adotada como item do catalogo publico e procura campo que nao ha.
    const { origin: legacy, ...rest } = hunt || {};
    const adopted = ['hearth', 'ptbr'].includes(hunt?.adoptedFrom)
        ? hunt.adoptedFrom
        : (['hearth', 'ptbr'].includes(legacy) ? legacy : '');

    return {
        ...rest,
        adoptedFrom: adopted,
        sourceId: hunt?.sourceId || '',
        cadence: Object.hasOwn(CADENCES, hunt?.cadence) ? hunt.cadence : '',
        runs: Array.isArray(hunt?.runs) ? hunt.runs : [],
    };
}

/** Insere/atualiza no topo e corta o excedente mais antigo. */
export function upsertHunt(list = [], hunt, cap = HUNTS_CAP) {
    return [hunt, ...list.filter((item) => item.id !== hunt.id)].slice(0, cap);
}
