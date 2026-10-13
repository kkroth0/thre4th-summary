import test from "node:test";
import assert from "node:assert/strict";
import { matchActors, topTechniques, actorPageCopy } from "./actorsView.ts";

test("modelagem: setor pesa o dobro da região e ator sem interseção fica de fora", () => {
  const actors = [
    { id: "a", name: "Banco Hunter", technique_count: 20, techniques: ["T1566"], sectors: ["Financial"], targets: ["Brazil"] },
    { id: "b", name: "Regional", technique_count: 30, techniques: ["T1059.001"], sectors: ["Energy"], targets: ["Brazil"] },
    { id: "c", name: "Fora", technique_count: 99, techniques: ["T1486"], sectors: ["Healthcare"], targets: ["Japan"] },
  ];
  const profile = { id: "p", name: "Banco X", sectors: ["Financial"], regions: ["Brazil"] };

  const matches = matchActors(actors, profile);
  assert.deepEqual(matches.map((m) => m.actor.id), ["a", "b"]);
  assert.equal(matches[0].score, 3);
  assert.deepEqual(matches[0].sectorHits, ["Financial"]);

  const top = topTechniques(matches);
  assert.deepEqual(top, [
    { id: "T1059.001", actors: 1 },
    { id: "T1566", actors: 1 },
  ]);
});

test('modelagem: combina aliases e normaliza sem contar o mesmo setor duas vezes', () => {
  const matches = matchActors([{ id: 'a', name: 'Example', technique_count: 1, sectors: ['Financial', 'financial services', 'Financial'], targets: ['Brazil', 'Brazil'] }], { id: 'p', name: 'P', sectors: ['Finance'], regions: ['BR'] });
  assert.equal(matches.length, 1); assert.equal(matches[0].score, 3);
  assert.deepEqual(matches[0].sectorHits, ['Financial']); assert.deepEqual(matches[0].regionHits, ['Brazil']);
});

test('modelagem: exigir setor e região exclui correspondências parciais, sem exigir dimensão vazia', () => {
  const actors = [{ id: 'both', name: 'Both', technique_count: 1, sectors: ['Finance'], targets: ['Brazil'] }, { id: 'sector', name: 'Sector', technique_count: 2, sectors: ['Finance'], targets: ['Japan'] }];
  const profile = { id: 'p', name: 'P', sectors: ['Finance'], regions: ['Brazil'] };
  assert.deepEqual(matchActors(actors, profile, 'all').map(match => match.actor.id), ['both']);
  assert.equal(matchActors(actors, { ...profile, regions: [] }, 'all').length, 2);
});

test("a página se chama Atores de Ameaça em PT e ES", () => {
  assert.equal(actorPageCopy("pt").title, "Atores de Ameaça");
  assert.equal(actorPageCopy("es").title, "Actores de Amenaza");
  assert.equal(actorPageCopy("en").title, "Threat Actors");
  assert.equal(actorPageCopy("fr").title, "Acteurs de Menace");
});

test("nenhum idioma ainda chama de grupo de ataque", () => {
  for (const language of ["pt", "en", "es", "fr"] as const) {
    assert.doesNotMatch(actorPageCopy(language).title, /grupos? de ataque|groupes? d'attaque/i, language);
  }
});
