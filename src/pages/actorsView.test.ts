import test from "node:test";
import assert from "node:assert/strict";
import { actorHuntCoverage, sortActors, matchActors, topTechniques } from "./actorsView.ts";

const actors = [
  { id: "alpha", name: "Alpha", country: "BR", technique_count: 2, techniques: ["T1059", "T1078"] },
  { id: "bravo", name: "Bravo", country: "US", technique_count: 1, techniques: ["T1566"] },
  { id: "charlie", name: "Charlie", country: "US", technique_count: 1, techniques: ["T1078"] },
];

test("counts each private hunt once per actor even when two techniques match", () => {
  assert.deepEqual(actorHuntCoverage(actors, [
    { id: "h1", techniques: ["T1059", "T1078"] },
    { id: "h2", techniques: ["T1078"] },
  ]), { alpha: 2, bravo: 0, charlie: 2 });
});

test("sorts hunt coverage descending and breaks ties by actor name", () => {
  assert.deepEqual(
    sortActors(actors, "hunts", { alpha: 2, bravo: 0, charlie: 2 }).map((actor) => actor.id),
    ["alpha", "charlie", "bravo"],
  );
});

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

  // T1059.001 da hunt cobre o T1059.001 do ator; T1566 continua descoberto.
  const top = topTechniques(matches, new Set(["T1059.001"]));
  assert.deepEqual(top, [
    { id: "T1059.001", actors: 1, covered: true },
    { id: "T1566", actors: 1, covered: false },
  ]);
});
