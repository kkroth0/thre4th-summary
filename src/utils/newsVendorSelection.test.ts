import test from "node:test";
import assert from "node:assert/strict";
import { filterNewsVendors, setNewsVendorSelection, newsMonitoringCacheKey } from "./newsVendorSelection";

const vendors = [
  { id: "fortinet", name: "Fortinet", sector: "security", aliases: ["Fortinet", "FortiGate"] },
  { id: "cisco", name: "Cisco", sector: "networking", aliases: ["Cisco", "Cisco ASA"] },
  { id: "schneider-electric", name: "Schneider Electric", sector: "ot-ics", aliases: ["Schneider Electric", "EcoStruxure"] },
];

test("buscar por produto encontra o fornecedor e combina setor e seleção", () => {
  assert.deepEqual(filterNewsVendors(vendors, { search: "FORTIGATE" }).map((vendor) => vendor.id), ["fortinet"]);
  assert.deepEqual(filterNewsVendors(vendors, { sector: "networking" }).map((vendor) => vendor.id), ["cisco"]);
  assert.deepEqual(filterNewsVendors(vendors, { selectedOnly: true, selectedIds: ["fortinet"], search: "EcoStruxure" }), []);
});

test("seleção dos resultados preserva fornecedores escolhidos em outros setores", () => {
  assert.deepEqual(setNewsVendorSelection(["fortinet"], ["cisco"], true), ["cisco", "fortinet"]);
  assert.deepEqual(setNewsVendorSelection(["cisco", "fortinet"], ["cisco"], false), ["fortinet"]);
  assert.deepEqual(setNewsVendorSelection(["fortinet"], ["fortinet"], true), ["fortinet"]);
});

test("cache de notícias é isolado por conta e seleção, independente da ordem dos IDs", () => {
  const selected = { mode: "selected" as const, vendorIds: ["fortinet", "cisco"] };
  assert.equal(newsMonitoringCacheKey("a", selected), newsMonitoringCacheKey("a", { ...selected, vendorIds: ["cisco", "fortinet"] }));
  assert.notEqual(newsMonitoringCacheKey("a", selected), newsMonitoringCacheKey("b", selected));
  assert.notEqual(newsMonitoringCacheKey("a", selected), newsMonitoringCacheKey("a", { ...selected, vendorIds: ["fortinet"] }));
  assert.notEqual(newsMonitoringCacheKey("a", { ...selected, vendorIds: [] }), newsMonitoringCacheKey("a", { mode: "all", vendorIds: [] }));
});
