/**
 * Lógica pura do store de boletins (.feed-jobs.json).
 *
 * Um job que terminou É o boletim — ele já guarda o JSON completo e o dono.
 * O que faltava não era um segundo store, era parar de descartar o que deu
 * certo e conseguir listar. Estas duas funções cuidam disso; as rotas seguem
 * inline no index.js.
 */

/** Metadado do job sem o boletim. A lista carrega isso; o JSON só no detalhe. */
export function jobSummary(job) {
    const { json, ...meta } = job || {};
    return { ...meta, hasReport: Boolean(json) };
}

/**
 * Poda o store com duas regras diferentes, porque os dois tipos de job têm
 * valor diferente:
 *
 *   - `done` é entregue: é o boletim que o usuário vai consultar depois. Só sai
 *     quando o dono passa do teto dele, e aí sai o mais antigo desse dono.
 *   - `pending`/`error` é operacional: teto global, mais antigo primeiro.
 *
 * O corte antigo era um teto global de 100 sobre tudo. Bastavam 100 gerações de
 * qualquer usuário para apagar o boletim de outro — o que só não doía porque
 * ninguém listava os antigos.
 */
export function pruneJobsMap(store, { maxTransient = 100, keptPerOwner = 200 } = {}) {
    const byAge = (a, b) => (a.createdAt || '').localeCompare(b.createdAt || '');
    const jobs = Object.values(store || {});

    const transient = jobs.filter((j) => j.status !== 'done').sort(byAge);
    const drop = new Set(transient.slice(0, Math.max(0, transient.length - maxTransient)).map((j) => j.id));

    const doneByOwner = new Map();
    for (const job of jobs.filter((j) => j.status === 'done')) {
        const owner = job.ownerSub || '';
        if (!doneByOwner.has(owner)) doneByOwner.set(owner, []);
        doneByOwner.get(owner).push(job);
    }
    for (const list of doneByOwner.values()) {
        list.sort(byAge);
        for (const job of list.slice(0, Math.max(0, list.length - keptPerOwner))) drop.add(job.id);
    }

    for (const id of drop) delete store[id];
    return drop.size;
}
