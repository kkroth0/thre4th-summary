import test from "node:test";
import assert from "node:assert/strict";
import { actorHuntCoverage, sortActors } from "./actorsView.ts";

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
