import test from "node:test";
import assert from "node:assert/strict";
import { ORG_WEIGHTS, annotateOrg, orgRelevance, type OrgThreatModel } from "./orgRelevance";

const model = (over: Partial<OrgThreatModel> = {}): OrgThreatModel => ({
  actorIds: [],
  pinnedIds: [],
  actors: [],
  sectors: [],
  regions: [],
  otPresent: false,
  assets: [],
  techniques: [],
  ...over,
});

test("sem modelo, nada é relevante", () => {
  assert.deepEqual(orgRelevance({ title: "FortiGate RCE" }, null), { score: 0, matches: [] });
});

test("ativo do perfil citado no título", () => {
  const result = orgRelevance(
    { title: "Critical RCE in FortiGate appliances" },
    model({ assets: [{ vendor: "Fortinet", product: "FortiGate" }] }),
  );
  assert.equal(result.score, ORG_WEIGHTS.asset);
  assert.deepEqual(result.matches, [{ kind: "asset", label: "FortiGate" }]);
});

// Um termo de 3 letras dentro de outra palavra é exatamente o falso positivo que
// o mínimo de caracteres em orgProfiles.js tenta evitar — a fronteira fecha o resto.
test("ativo curto não casa dentro de outra palavra", () => {
  const result = orgRelevance({ title: "Sapphire Rapids benchmark" }, model({ assets: [{ vendor: "", product: "SAP" }] }));
  assert.equal(result.score, 0);
  assert.deepEqual(orgRelevance({ title: "SAP patch day" }, model({ assets: [{ vendor: "", product: "SAP" }] })).score, ORG_WEIGHTS.asset);
});

test("ator relevante e ator fixado têm pesos diferentes", () => {
  const relevant = model({ actorIds: ["G0034"], actors: [{ id: "G0034", name: "Sandworm", country: "Russia" }] });
  assert.equal(orgRelevance({ title: "x", actors: [{ id: "G0034" }] }, relevant).score, ORG_WEIGHTS.actor);

  const pinnedModel = model({ ...relevant, pinnedIds: ["G0034"] });
  const pinned = orgRelevance({ title: "x", actors: [{ id: "G0034" }] }, pinnedModel);
  assert.equal(pinned.score, ORG_WEIGHTS.actorPinned);
  assert.deepEqual(pinned.matches, [{ kind: "actor", label: "Sandworm", pinned: true }]);
});

test("ator fora do modelo não pontua", () => {
  assert.equal(orgRelevance({ title: "x", actors: [{ id: "G9999" }] }, model({ actorIds: ["G0034"] })).score, 0);
});

test("o mesmo ator repetido conta uma vez", () => {
  const result = orgRelevance(
    { title: "x", actors: [{ id: "G0034" }, { id: "G0034" }] },
    model({ actorIds: ["G0034"], actors: [{ id: "G0034", name: "Sandworm", country: "Russia" }] }),
  );
  assert.equal(result.score, ORG_WEIGHTS.actor);
  assert.equal(result.matches.length, 1);
});

test("setor vem do campo que o servidor já carimba", () => {
  const result = orgRelevance({ title: "x", sectors: ["Energy", "Retail"] }, model({ sectors: ["Energy"] }));
  assert.equal(result.score, ORG_WEIGHTS.sector);
  assert.deepEqual(result.matches, [{ kind: "sector", label: "Energy" }]);
});

test("OT só pontua quando o perfil tem OT", () => {
  const otItem = { title: "x", newsCategories: ["OT/ICS"] };
  assert.equal(orgRelevance(otItem, model({ otPresent: true })).score, ORG_WEIGHTS.ot);
  assert.equal(orgRelevance(otItem, model({ otPresent: false })).score, 0);
});

test("região casa por termo, ignorando acento e caixa", () => {
  const brazil = model({ regions: [{ label: "Brazil", terms: ["brazil", "brazilian"] }] });
  assert.equal(orgRelevance({ title: "Brazilian banks hit" }, brazil).score, ORG_WEIGHTS.region);
  assert.equal(orgRelevance({ title: "BRAZIL under attack" }, brazil).score, ORG_WEIGHTS.region);
  assert.equal(orgRelevance({ title: "Nothing here" }, brazil).score, 0);
});

test("a descrição também é lida", () => {
  const result = orgRelevance({ title: "Advisory", description: "affects FortiGate 7.x" }, model({ assets: [{ vendor: "", product: "FortiGate" }] }));
  assert.equal(result.score, ORG_WEIGHTS.asset);
});

test("a soma tem teto de 100", () => {
  const rich = model({
    assets: [{ vendor: "", product: "FortiGate" }, { vendor: "", product: "ESXi" }],
    actorIds: ["G0034"],
    pinnedIds: ["G0034"],
    actors: [{ id: "G0034", name: "Sandworm", country: "Russia" }],
    sectors: ["Energy"],
    otPresent: true,
    regions: [{ label: "Brazil", terms: ["brazil"] }],
  });
  const result = orgRelevance(
    { title: "FortiGate and ESXi hit in Brazil", sectors: ["Energy"], actors: [{ id: "G0034" }], newsCategories: ["OT/ICS"] },
    rich,
  );
  assert.equal(result.score, 100);
});

test("annotateOrg carimba orgScore e orgMatches sem mexer no resto", () => {
  const items = [{ title: "FortiGate RCE", link: "a" }, { title: "Nada a ver", link: "b" }];
  const annotated = annotateOrg(items, model({ assets: [{ vendor: "", product: "FortiGate" }] }));
  assert.equal(annotated[0].orgScore, ORG_WEIGHTS.asset);
  assert.equal(annotated[0].link, "a");
  assert.equal(annotated[1].orgScore, 0);
  assert.deepEqual(annotated[1].orgMatches, []);
});
