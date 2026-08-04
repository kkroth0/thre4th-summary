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

// Identificador legivel: TH-<ano>-<sequencial>. O hex aleatorio funcionava pra
// maquina, mas ninguem diz "olha a 8f3a91c2e004" numa reuniao.
const HUNT_ID = /^TH-(\d{4})-(\d{3,})$/;

/**
 * Proximo id do ano. Numero nunca volta: o `floor` e a marca d'agua gravada em
 * disco, entao apagar a ultima hunt do ano nao faz a contagem recomecar. Sem
 * ele, um "TH-2026-001" citado em relatorio antigo passaria a apontar pra outra
 * hunt — que e exatamente o que um id serve pra evitar.
 *
 * A lista ainda entra no calculo pra cobrir quem ja tinha hunts antes do
 * contador existir.
 */
export function nextHuntId(list = [], year = new Date().getUTCFullYear(), floor = 0) {
    const naLista = (list || []).reduce((max, hunt) => {
        const match = HUNT_ID.exec(String(hunt?.id ?? ''));
        if (!match || Number(match[1]) !== year) return max;
        return Math.max(max, Number(match[2]));
    }, 0);

    // Passou de 999 o ano vira quatro digitos em vez de estourar o formato.
    return `TH-${year}-${String(Math.max(naLista, floor) + 1).padStart(3, '0')}`;
}

/** O numero de um id nosso, pra gravar a marca d'agua. 0 se nao for do formato. */
export function huntIdSeq(id) {
    const match = HUNT_ID.exec(String(id ?? ''));
    return match ? Number(match[2]) : 0;
}

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
 * Agenda de todas as hunts com ritmo definido: quando rodou, quando vence e
 * quanto esta atrasada. E a visao continua — o resumo do mes responde "o que
 * aconteceu em agosto", isto responde "onde tudo esta agora".
 *
 * Sem cadencia a hunt fica de fora: quem nao combinou ritmo nao esta atrasado.
 */
export function huntSchedule(list = [], now = Date.now()) {
    const dia = 24 * 60 * 60 * 1000;

    return list
        .map((hunt) => {
            const days = CADENCES[hunt.cadence];
            if (!days) return null;

            // A execucao que vale e a mais recente por data. A lista guarda a mais
            // nova no topo, mas reabrir mexe na ordem — nao da pra confiar nela.
            const last = (hunt.runs || [])
                .map((run) => Date.parse(run.startedAt))
                .filter(Number.isFinite)
                .sort((a, b) => b - a)[0];

            const dueMs = days * dia;
            const nextDue = last === undefined ? now : last + dueMs;
            const late = now >= nextDue;

            return {
                id: hunt.id,
                title: hunt.title,
                cadence: hunt.cadence,
                lastRunAt: last === undefined ? null : new Date(last).toISOString(),
                nextDueAt: last === undefined ? null : new Date(nextDue).toISOString(),
                // Nunca rodou nao tem "dias de atraso": nao ha de quando contar.
                daysLate: late && last !== undefined ? Math.floor((now - nextDue) / dia) : null,
                late,
            };
        })
        .filter(Boolean)
        // Nunca rodou primeiro, depois o mais atrasado, depois o que vence antes.
        .sort((a, b) => {
            if (a.late !== b.late) return a.late ? -1 : 1;
            if ((a.lastRunAt === null) !== (b.lastRunAt === null)) return a.lastRunAt === null ? -1 : 1;
            if (a.late) return (b.daysLate ?? 0) - (a.daysLate ?? 0);
            return Date.parse(a.nextDueAt) - Date.parse(b.nextDueAt);
        });
}

/** So o que ja venceu — o alerta do painel sai daqui, sem regra duplicada. */
export function overdueHunts(list = [], now = Date.now()) {
    return huntSchedule(list, now).filter((item) => item.late);
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
