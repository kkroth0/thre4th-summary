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
