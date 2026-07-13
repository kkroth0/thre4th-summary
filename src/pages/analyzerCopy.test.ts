import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("primary analyzer copy names IPv4/IPv6, domain, URL, and hash in PT and EN", () => {
  const sources = [
    readFileSync(new URL("src/pages/Index.tsx", `file://${process.cwd()}/`), "utf8"),
    readFileSync(new URL("src/components/SearchForm.tsx", `file://${process.cwd()}/`), "utf8"),
  ].join("\n");

  assert.match(sources, /IPv4\/IPv6, dominio, URL ou hash/);
  assert.match(sources, /IPv4\/IPv6, domain, URL, or hash/);
  assert.doesNotMatch(sources, /IPv4\/IPv6[^"\n]*(?:CVE|ASN)/i);
});
