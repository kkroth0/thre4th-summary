// Casa uma notícia com o contexto da organização.
//
// Roda no cliente de propósito: a tela de Notícias agrupa histórias no
// navegador e guarda até 400 itens em localStorage por dias. Anotar no servidor
// deixaria a anotação velha assim que o usuário trocasse de perfil; recalcular
// aqui reanota os 400 na hora, sem invalidação nenhuma.
//
// Nada de vocabulário próprio: setor vem de `item.sectors` (carimbado por
// scoreArticle), OT vem de `item.newsCategories`, ator vem de `item.actors`, e
// os termos de região vêm dentro do próprio modelo.

export interface OrgThreatModel {
  actorIds: string[];
  pinnedIds: string[];
  actors: { id: string; name: string; country: string }[];
  sectors: string[];
  regions: { label: string; terms: string[] }[];
  otPresent: boolean;
  assets: { vendor: string; product: string }[];
  techniques: string[];
}

export interface OrgMatch {
  kind: "asset" | "actor" | "sector" | "ot" | "region";
  label: string;
  pinned?: boolean;
}

export interface OrgRelevance {
  score: number;
  matches: OrgMatch[];
}

export interface OrgSubject {
  title?: string;
  description?: string;
  actors?: { id: string; name?: string }[];
  sectors?: string[];
  newsCategories?: string[];
}

export const ORG_WEIGHTS = {
  asset: 40,
  actorPinned: 40,
  actor: 30,
  sector: 20,
  ot: 20,
  region: 15,
} as const;

const normalize = (value: string): string =>
  value.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");

const escapeRe = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Fronteira alfanumérica em vez de \b: nomes de produto carregam ponto e hífen
// (Node.js, Allen-Bradley), onde \b cai em lugares errados. Sem lookbehind,
// porque só interessa saber se casou.
const hasTerm = (haystack: string, term: string): boolean => {
  const clean = normalize(term).trim();
  if (!clean) return false;
  return new RegExp(`(^|[^a-z0-9])${escapeRe(clean)}($|[^a-z0-9])`).test(haystack);
};

export const orgRelevance = (subject: OrgSubject, model: OrgThreatModel | null | undefined): OrgRelevance => {
  if (!model) return { score: 0, matches: [] };

  const text = normalize(`${subject.title ?? ""} ${subject.description ?? ""}`);
  const matches: OrgMatch[] = [];
  let score = 0;

  for (const asset of model.assets) {
    const matched = asset.product && hasTerm(text, asset.product)
      ? asset.product
      : asset.vendor && hasTerm(text, asset.vendor)
        ? asset.vendor
        : "";
    if (!matched) continue;
    matches.push({ kind: "asset", label: matched });
    score += ORG_WEIGHTS.asset;
  }

  const relevantActors = new Set(model.actorIds);
  const pinnedActors = new Set(model.pinnedIds);
  const actorName = new Map(model.actors.map((actor) => [actor.id, actor.name]));
  const countedActors = new Set<string>();
  for (const actor of subject.actors ?? []) {
    if (!relevantActors.has(actor.id) || countedActors.has(actor.id)) continue;
    countedActors.add(actor.id);
    const pinned = pinnedActors.has(actor.id);
    matches.push({ kind: "actor", label: actorName.get(actor.id) ?? actor.name ?? actor.id, ...(pinned ? { pinned: true } : {}) });
    score += pinned ? ORG_WEIGHTS.actorPinned : ORG_WEIGHTS.actor;
  }

  const profileSectors = new Set(model.sectors);
  for (const sector of subject.sectors ?? []) {
    if (!profileSectors.has(sector)) continue;
    matches.push({ kind: "sector", label: sector });
    score += ORG_WEIGHTS.sector;
  }

  if (model.otPresent && (subject.newsCategories ?? []).includes("OT/ICS")) {
    matches.push({ kind: "ot", label: "OT/ICS" });
    score += ORG_WEIGHTS.ot;
  }

  for (const region of model.regions) {
    if (!region.terms.some((term) => hasTerm(text, term))) continue;
    matches.push({ kind: "region", label: region.label });
    score += ORG_WEIGHTS.region;
  }

  return { score: Math.min(score, 100), matches };
};

export const annotateOrg = <T extends OrgSubject>(
  items: T[],
  model: OrgThreatModel | null | undefined,
): (T & { orgScore: number; orgMatches: OrgMatch[] })[] =>
  items.map((item) => {
    const { score, matches } = orgRelevance(item, model);
    return { ...item, orgScore: score, orgMatches: matches };
  });
