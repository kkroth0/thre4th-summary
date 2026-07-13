import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("localizes the geographic and network title in every supported language", () => {
  const source = readFileSync(new URL("src/components/GeographicNetworkOverview.tsx", `file://${process.cwd()}/`), "utf8");

  assert.match(source, /const \{ tr \} = useLanguage\(\)/);
  assert.match(source, /tr\(\{[\s\S]*pt: "Dados geográficos e de rede"[\s\S]*en: "Geographic & Network Data"[\s\S]*es: "Datos geográficos y de red"[\s\S]*fr: "Données géographiques et réseau"[\s\S]*\}\)/);
});
