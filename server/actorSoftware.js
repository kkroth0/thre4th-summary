// Índice família de malware → grupos, para o enriquecimento de indicadores.
//
// ThreatFox e VirusTotal quase sempre devolvem a família ("QakBot", "Emotet") e
// nunca o grupo; o catálogo de atores guarda o inverso — cada ator lista o
// software que usa. Este índice fecha a ponte no sentido que o enriquecimento
// precisa.
//
// A chave é normalizada porque a mesma família aparece escrita de três jeitos
// nas bases: "Gh0st RAT", "gh0strat", "Gh0stRAT".

const PLACEHOLDER = '[unnamed group]';

export const softwareKey = (name) =>
    String(name || '')
        .toLowerCase()
        .normalize('NFD')
        .replace(/\p{Mn}/gu, '')
        .replace(/[^a-z0-9]/g, '');

export const buildSoftwareIndex = (actors) => {
    const index = {};
    for (const actor of actors || []) {
        // Grupo sem nome não atribui nada — "[Unnamed group]" numa planilha de
        // cliente é pior do que a célula vazia.
        if (!actor?.name || actor.name.toLowerCase() === PLACEHOLDER) continue;
        for (const software of actor.software || []) {
            const name = typeof software === 'string' ? software : software?.name;
            const key = softwareKey(name);
            if (!key) continue;
            const bucket = (index[key] ||= []);
            // O mesmo ator pode listar a mesma ferramenta duas vezes (alias no
            // catálogo de origem); a planilha não pode contar duas vezes.
            if (!bucket.some((entry) => entry.id === actor.id)) {
                bucket.push({ id: actor.id, name: actor.name });
            }
        }
    }
    return index;
};

// Índice nome/alias → nome canônico do ator.
//
// O campo `adversary` do pulse da OTX é texto livre, e analista escreve nele o
// que quiser: medido em 2026-08-27, de 26 rótulos vindos de dois indicadores
// reais, só 5 eram ator — o resto era nome de malware ("WordlistLoader"),
// rótulo de campanha ("M365 AiTM PhaaS") e até título de artigo ("FTP Banners:
// Dead Drop Res"). Sem passar por aqui, a coluna Grupo da planilha saía com 21
// nomes, e nenhum cliente lê isso.
//
// O alias também colapsa duplicata: UNC2452 e APT29 viram uma linha só.
export const buildActorNameIndex = (actors) => {
    const index = {};
    for (const actor of actors || []) {
        if (!actor?.name || actor.name.toLowerCase() === PLACEHOLDER) continue;
        for (const label of [actor.name, ...(actor.aliases || [])]) {
            const key = softwareKey(label);
            // O primeiro a reivindicar a chave fica: alias colidindo entre dois
            // atores é raro e ambíguo, e trocar de dono a cada rebuild seria pior.
            if (key && !index[key]) index[key] = actor.name;
        }
    }
    return index;
};
