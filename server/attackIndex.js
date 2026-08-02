/**
 * O índice que liga Intel, Hunting e Detection.
 *
 * A regra é uma só: toda entidade (report, hunt, item de knowledge, ator)
 * carrega `techniques[]` e `cves[]`, e todo cruzamento entre elas é interseção
 * sobre esses dois campos. Nada aqui faz I/O — a taxonomia vem de
 * server/data/attack.json, gerada por scripts/build-actors.mjs.
 */

// Mesmo par de padrões que src/components/BoletimView.tsx usa para linkificar
// prosa. `src/` e `server/` não compartilham diretório e são empacotados por
// ferramentas diferentes, então duplicar dois regexes sai mais barato que criar
// o primeiro módulo compartilhado do projeto.
const TECHNIQUE_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi;

const up = (v) => String(v ?? '').toUpperCase();
const uniq = (arr) => [...new Set(arr)].sort();

/** Técnicas chegam como "T1059" ou como {id,name,url} (actors.json, mitre_ttps). */
const idOf = (t) => up(typeof t === 'string' ? t : t?.id);

/** Varre texto livre atrás de IDs de técnica e CVE. */
export function extractRefs(text) {
    const s = typeof text === 'string' ? text : '';
    return {
        techniques: uniq((s.match(TECHNIQUE_RE) || []).map(up)),
        cves: uniq((s.match(CVE_RE) || []).map(up)),
    };
}

/**
 * Refs de um boletim. Serializar e varrer o JSON inteiro pega de uma vez
 * `mitre_ttps[].id`, `cve_id`, `tecnologias_afetadas[].cve` e qualquer ID citado
 * na prosa — que é exatamente o conjunto que queremos indexar.
 */
export const refsOfReport = (boletim) => extractRefs(JSON.stringify(boletim ?? {}));

/**
 * Dado um alvo {techniques, cves}, filtra cada pool pelas entidades que
 * compartilham ao menos uma técnica ou CVE. Genérico no formato do pool:
 * relatedTo(refs, { hunts, reports, actors }) devolve as mesmas chaves.
 */
export function relatedTo({ techniques = [], cves = [] } = {}, pools = {}) {
    const wantT = new Set(techniques.map(idOf));
    const wantC = new Set(cves.map(up));
    const hit = (item) =>
        (item?.techniques || []).some((t) => wantT.has(idOf(t))) ||
        (item?.cves || []).some((c) => wantC.has(up(c)));
    return Object.fromEntries(
        Object.entries(pools).map(([key, list]) => [key, (list || []).filter(hit)]),
    );
}

/**
 * Agrupa entidades por um campo de lista (`technologies`, `dataSources`) e
 * devolve os valores ordenados por frequência. É a cobertura por tecnologia e
 * por tabela de log — sem denominador, porque não existe catálogo fechado
 * dessas duas dimensões.
 */
export function groupByField(items, field) {
    const counts = new Map();
    for (const item of items || []) {
        for (const raw of item?.[field] || []) {
            const value = String(raw ?? '').trim();
            if (value) counts.set(value, (counts.get(value) || 0) + 1);
        }
    }
    return [...counts.entries()]
        .map(([value, count]) => ({ value, count }))
        .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

/**
 * Cobertura sobre a matriz ATT&CK: para cada tática, as técnicas de topo com
 * suas sub-técnicas e quantas entidades cobrem cada uma.
 *
 * Estados, iguais aos da matriz de referência:
 *   covered — alguma entidade aponta para a própria técnica
 *   partial — nenhuma aponta para ela, mas alguma cobre uma sub-técnica
 *   none    — nada
 *
 * Uma técnica pertencente a N táticas aparece nas N colunas; é assim no ATT&CK.
 */
export function techniqueCoverage(items, taxonomy) {
    const direct = new Map();
    for (const item of items || []) {
        for (const t of item?.techniques || []) {
            const id = idOf(t);
            if (id) direct.set(id, (direct.get(id) || 0) + 1);
        }
    }

    const all = taxonomy?.techniques || [];
    const subsOf = new Map();
    for (const t of all) {
        if (!t.id.includes('.')) continue;
        const parent = t.id.split('.')[0];
        if (!subsOf.has(parent)) subsOf.set(parent, []);
        subsOf.get(parent).push(t);
    }

    const node = (t) => {
        const count = direct.get(t.id) || 0;
        const subs = (subsOf.get(t.id) || []).map((s) => ({
            id: s.id,
            name: s.name,
            count: direct.get(s.id) || 0,
            state: direct.get(s.id) ? 'covered' : 'none',
        }));
        const state = count ? 'covered' : subs.some((s) => s.count) ? 'partial' : 'none';
        return { id: t.id, name: t.name, count, state, subs };
    };

    const tactics = (taxonomy?.tactics || []).map((tactic) => {
        const techniques = all
            .filter((t) => !t.id.includes('.') && (t.tactics || []).includes(tactic.shortname))
            .map(node);
        return {
            ...tactic,
            techniques,
            covered: techniques.filter((t) => t.state === 'covered').length,
            total: techniques.length,
        };
    });

    // Denominador global = toda a matriz (técnicas + sub-técnicas), como no
    // "2 of 697" da referência. Só conta o que existe na taxonomia: um ID solto
    // numa entidade não infla a cobertura.
    const known = new Set(all.map((t) => t.id));
    const covered = [...direct.keys()].filter((id) => known.has(id)).length;
    return { tactics, covered, total: known.size };
}
