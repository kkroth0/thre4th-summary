import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("primary analyzer copy names IPv4/IPv6, domain, URL, and hash in PT and EN", () => {
  const sources = [
    readFileSync("src/pages/Index.tsx", "utf8"),
    readFileSync("src/components/SearchForm.tsx", "utf8"),
  ].join("\n");

  assert.match(sources, /IPv4\/IPv6, domínio, URL ou hash/);
  assert.match(sources, /IPv4\/IPv6, domain, URL, or hash/);
  assert.doesNotMatch(sources, /IPv4\/IPv6[^"\n]*(?:CVE|ASN)/i);
});
