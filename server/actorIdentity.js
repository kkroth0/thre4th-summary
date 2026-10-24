// One identity policy for catalog display, structured providers and text matching.
export const actorNameKey = value => String(value || '').normalize('NFKD').replace(/\p{Mn}/gu, '').toLowerCase().replace(/[^a-z0-9]/g, '');
const mitre = actor => /^G\d{4}$/.test(actor.id || '');
const unique = (rows, key) => [...new Map(rows.map(row => [key(row), row])).values()];

export function canonicalizeActors(input = []) {
  const rows = input.map(actor => ({ ...actor, aliases: [...(actor.aliases || [])], redirectIds: [...(actor.redirectIds || [])],
    identitySources: [...(actor.identitySources || [])], relatedNames: [...(actor.relatedNames || [])] }));
  const authoritative = new Map();
  for (const actor of rows.filter(mitre)) for (const name of [actor.name, ...actor.aliases]) {
    const key = actorNameKey(name), owners = authoritative.get(key) || new Map(); owners.set(actor.id, actor); authoritative.set(key, owners);
  }
  const trustedNames=new Map();
  for(const actor of rows)if(!actor.verification&&actor.source!=='CTI.fyi')for(const name of [actor.name,...actor.aliases]){
    const key=actorNameKey(name),bucket=trustedNames.get(key)||new Map();bucket.set(actor.id,actor);trustedNames.set(key,bucket);
  }
  const retained = [], byName = new Map();
  for (const actor of [...rows.filter(mitre), ...rows.filter(row => !mitre(row))]) {
    const key = actorNameKey(actor.name), owners = authoritative.get(key);
    // Separate MITRE groups (including subgroups) never collapse via a shared alias.
    const sourceOnly=actor.verification==='source-reported'||/^(?:axur:|otx:|cti-fyi:)/.test(actor.id||'');
    const trustedOwners=sourceOnly?new Map([...(trustedNames.get(key)||[])].filter(([id])=>id!==actor.id)):new Map();
    const target = !mitre(actor) && owners?.size === 1 ? [...owners.values()][0]
      : !mitre(actor) && trustedOwners.size === 1 ? [...trustedOwners.values()][0]
      : !mitre(actor) && (actor.source||sourceOnly) && byName.get(key)?.length === 1 ? byName.get(key)[0] : null;
    if (target && target.id !== actor.id) {
      target.redirectIds.push(actor.id, ...actor.redirectIds);
      target.aliases.push(actor.name, ...actor.aliases);
      target.identitySources.push({ id: actor.id, name: actor.name, source: actor.source || '', relation: 'catalog-name-equivalence' }, ...actor.identitySources);
      for (const field of ['refs', 'aliasEvidence', 'relatedNames', 'infrastructure']) target[field] = unique([...(target[field] || []), ...(actor[field] || [])], row => JSON.stringify(row));
      for (const field of ['description', 'country', 'motivation']) if (!target[field] && actor[field]) target[field] = actor[field];
      continue;
    }
    retained.push(actor); const bucket = byName.get(key) || []; bucket.push(actor); byName.set(key, bucket);
  }
  const owners = new Map();
  for (const actor of retained) for (const name of [actor.name, ...actor.aliases,...actor.relatedNames.filter(row=>row.identityAmbiguous).map(row=>row.name)]) {
    const key = actorNameKey(name), ids = owners.get(key) || new Set(); ids.add(actor.id); owners.set(key, ids);
  }
  for (const actor of retained) {
    const own = actorNameKey(actor.name), seen = new Set([own]);
    actor.aliases = actor.aliases.filter(name => {
      const key = actorNameKey(name); if (!key || seen.has(key)) return false; seen.add(key);
      const others = [...owners.get(key)].filter(id => id !== actor.id);
      if (others.length) {
        if (!actor.relatedNames.some(row => actorNameKey(row.name) === key)) actor.relatedNames.push({ name, source: actor.source || 'catalog', relation: 'source-association', identityAmbiguous:true, relatedActorIds: others });
        return false;
      }
      return true;
    });
    actor.redirectIds = [...new Set(actor.redirectIds)].filter(id => id !== actor.id);
    actor.identitySources = unique(actor.identitySources, row => `${row.id}:${row.source}`);
  }
  // Preserve the caller's order; identity selection never depends on sort order.
  const rank = new Map(input.map((actor, i) => [actor.id, i]));
  return retained.sort((a, b) => rank.get(a.id) - rank.get(b.id));
}

export function buildActorIdentityIndex(catalog) {
  const actors = canonicalizeActors(catalog), names = new Map(), ids = new Map();
  for (const actor of actors) {
    for (const id of [actor.id, ...actor.redirectIds]) ids.set(id, actor);
    if (/^\[/.test(actor.name || '')) continue;
    for (const label of [actor.name, ...actor.aliases]) {
      const key = actorNameKey(label), bucket = names.get(key) || new Map(); bucket.set(actor.id, { id: actor.id, name: actor.name, matched: label, via: 'exact' }); names.set(key, bucket);
    }
  }
  return { actors, ids, resolve: name => { const bucket = names.get(actorNameKey(name)); return bucket?.size === 1 ? [...bucket.values()][0] : null; } };
}

export function canonicalActorReferences(rows, identities) {
  return rows.map(row=>({...row,actors:unique((row.actors||[]).map(actor=>{
    const canonical=identities.ids.get(actor.id)||identities.resolve(actor.name);
    return canonical?{...actor,id:canonical.id,name:canonical.name}:actor;
  }),actor=>actor.id)}));
}
