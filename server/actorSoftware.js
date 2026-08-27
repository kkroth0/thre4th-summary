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
