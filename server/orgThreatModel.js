// Modelo de ameaças de um perfil: quem ataca gente como você.
//
// Puro sobre o catálogo que loadActors() já mantém em memória — cada ator chega
// com `sectors` e `targets` derivados da descrição por actorProfile.js, então
// não há dado novo a buscar, só um cruzamento.
//
// O retorno é JSON puro porque viaja até o navegador: o casamento notícia↔perfil
// roda no cliente, sobre os campos que o feed já traz.
import { TARGET_REGIONS } from './actorProfile.js';

export function buildThreatModel(profile, actors) {
    const sectors = new Set(profile?.sectors || []);
    const regions = new Set(profile?.regions || []);
    const pinned = new Set(profile?.actors || []);

    const relevant = [];
    for (const actor of Array.isArray(actors) ? actors : []) {
        if (!actor || !actor.id) continue;
        const bySector = (actor.sectors || []).some((sector) => sectors.has(sector));
        const byRegion = (actor.targets || []).some((target) => regions.has(target));
        if (bySector || byRegion || pinned.has(actor.id)) relevant.push(actor);
    }

    const techniques = new Set();
    for (const actor of relevant) {
        for (const technique of actor.techniques || []) if (technique?.id) techniques.add(technique.id);
    }

    return {
        actorIds: relevant.map((actor) => actor.id),
        pinnedIds: relevant.filter((actor) => pinned.has(actor.id)).map((actor) => actor.id),
        actors: relevant.map((actor) => ({ id: actor.id, name: actor.name, country: actor.country || '' })),
        sectors: [...sectors],
        // Os termos vão junto porque só o servidor tem o TARGET_REGIONS, e o
        // cliente precisa deles para reconhecer "brazilian" num título.
        regions: [...regions].map((label) => ({ label, terms: TARGET_REGIONS[label] || [] })),
        otPresent: Boolean(profile?.ot?.present),
        assets: (profile?.assets || []).map((asset) => ({ vendor: asset.vendor || '', product: asset.product || '' })),
        techniques: [...techniques].sort(),
    };
}
