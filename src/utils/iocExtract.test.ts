import test from "node:test";
import assert from "node:assert/strict";
import {
  detectAnalyzerQueryType,
  extractIocsFromText,
  isSupportedAnalyzerQuery,
} from "./iocExtract.ts";

test("extracts supported IOC types and excludes CVE identifiers", () => {
  const text = [
    "8.8.8.8 example.com https://example.com/path",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "CVE-2024-3094",
  ].join("\n");

  assert.deepEqual(extractIocsFromText(text), [
    "8.8.8.8",
    "https://example.com/path",
    "example.com",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  ]);
});

test("classifies only supported primary-search inputs", () => {
  assert.equal(detectAnalyzerQueryType("8.8.8.8"), "ip");
  assert.equal(detectAnalyzerQueryType("example.com"), "domain");
  assert.equal(detectAnalyzerQueryType("https://example.com/a"), "url");
  assert.equal(detectAnalyzerQueryType("d41d8cd98f00b204e9800998ecf8427e"), "hash");
  assert.equal(detectAnalyzerQueryType("CVE-2024-3094"), "unknown");
  assert.equal(detectAnalyzerQueryType("AS15169"), "unknown");
  assert.equal(isSupportedAnalyzerQuery("999.1.1.1"), false);
});
