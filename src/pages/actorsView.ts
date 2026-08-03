type Actor = {
  id: string;
  name: string;
  country?: string;
  technique_count: number;
  techniques?: string[];
};

type Hunt = { id: string; techniques?: string[] };

export function actorHuntCoverage<A extends Actor, H extends Hunt>(actors: A[], hunts: H[]): Record<string, number> {
  const huntIdsByTechnique = new Map<string, Set<string>>();
  for (const hunt of hunts) {
    for (const technique of hunt.techniques || []) {
      const ids = huntIdsByTechnique.get(technique) || new Set<string>();
      ids.add(hunt.id);
      huntIdsByTechnique.set(technique, ids);
    }
  }

  return Object.fromEntries(actors.map((actor) => {
    const huntIds = new Set<string>();
    for (const technique of actor.techniques || []) {
      huntIdsByTechnique.get(technique)?.forEach((id) => huntIds.add(id));
    }
    return [actor.id, huntIds.size];
  }));
}

export function sortActors<A extends Actor>(actors: A[], mode: "techniques" | "name" | "country" | "hunts", coverage: Record<string, number>): A[] {
  return [...actors].sort((a, b) => {
    if (mode === "name") return a.name.localeCompare(b.name);
    if (mode === "country") {
      return (a.country || "zz").localeCompare(b.country || "zz")
        || b.technique_count - a.technique_count
        || a.name.localeCompare(b.name);
    }
    if (mode === "hunts") return (coverage[b.id] || 0) - (coverage[a.id] || 0) || a.name.localeCompare(b.name);
    return b.technique_count - a.technique_count || a.name.localeCompare(b.name);
  });
}
