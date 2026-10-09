type Actor = {
  id: string;
  name: string;
  country?: string;
  technique_count: number;
  techniques?: string[];
  /** Setores atacados, derivados da descrição no servidor. */
  sectors?: string[];
  /** Países/regiões atacados, derivados da descrição no servidor. */
  targets?: string[];
};

export function sortActors<A extends Actor>(actors: A[], mode: "techniques" | "name" | "country"): A[] {
  return [...actors].sort((a, b) => {
    if (mode === "name") return a.name.localeCompare(b.name);
    if (mode === "country") {
      return (a.country || "zz").localeCompare(b.country || "zz")
        || b.technique_count - a.technique_count
        || a.name.localeCompare(b.name);
    }
    return b.technique_count - a.technique_count || a.name.localeCompare(b.name);
  });
}

// ─── Modelagem de ameaças ──────────────────────────────────────────────────
// Um perfil descreve UMA organização: em que setores ela está e em que
// países/regiões ela opera. O casamento com o catálogo responde "quem ataca
// gente como eu".

export type OrgProfile = {
  id: string;
  name: string;
  sectors: string[];
  regions: string[];
};

export type ActorMatch<A> = { actor: A; sectorHits: string[]; regionHits: string[]; score: number };

const overlap = (a: string[] | undefined, b: string[]) => (a || []).filter((value) => b.includes(value));

/**
 * Atores que atacam o setor OU a região do perfil, do mais aderente ao menos.
 * Setor pesa o dobro da região: quem ataca o seu ramo é mais relevante que
 * quem só passa pelo seu continente.
 */
export function matchActors<A extends Actor>(actors: A[], profile: OrgProfile): ActorMatch<A>[] {
  return actors
    .map((actor) => {
      const sectorHits = overlap(actor.sectors, profile.sectors);
      const regionHits = overlap(actor.targets, profile.regions);
      return { actor, sectorHits, regionHits, score: sectorHits.length * 2 + regionHits.length };
    })
    .filter((match) => match.score > 0)
    .sort((a, b) =>
      b.score - a.score
      || b.actor.technique_count - a.actor.technique_count
      || a.actor.name.localeCompare(b.actor.name));
}

/** TTPs mais usados pelos atores casados, do mais recorrente pro menos. */
export function topTechniques<A extends Actor>(
  matches: ActorMatch<A>[],
  limit = 12,
): Array<{ id: string; actors: number }> {
  const counts = new Map<string, number>();
  for (const { actor } of matches) {
    for (const technique of new Set(actor.techniques || [])) {
      counts.set(technique, (counts.get(technique) || 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([id, actors]) => ({ id, actors }))
    .sort((a, b) => b.actors - a.actors || a.id.localeCompare(b.id))
    .slice(0, limit);
}

// The page and the nav item have to agree, so the label lives here instead of
// being spelled out in both — this page used to be named differently.
const ACTOR_PAGE_TITLES: Record<string, string> = {
  pt: "Atores de Ameaça",
  en: "Threat Actors",
  es: "Actores de Amenaza",
  fr: "Acteurs de Menace",
};

export const actorPageCopy = (language: string) => ({
  title: ACTOR_PAGE_TITLES[language] ?? ACTOR_PAGE_TITLES.en,
});
