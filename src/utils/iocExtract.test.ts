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

test("accepts only public IPv4 addresses in primary search and extraction", () => {
  const nonPublicAddresses = [
    "10.0.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.16.0.1",
    "192.168.1.1",
    "100.64.0.1",
    "224.0.0.1",
    "0.0.0.0",
  ];

  assert.equal(detectAnalyzerQueryType("8.8.8.8"), "ip");
  for (const address of nonPublicAddresses) {
    assert.equal(detectAnalyzerQueryType(address), "unknown", address);
  }
  assert.deepEqual(
    extractIocsFromText(["8.8.8.8", ...nonPublicAddresses].join(" ")),
    ["8.8.8.8"],
  );
});

test("handles globally reachable exceptions in special-use IPv4 ranges", () => {
  assert.equal(detectAnalyzerQueryType("192.0.0.9"), "ip");
  assert.equal(detectAnalyzerQueryType("192.0.0.10"), "ip");
  assert.equal(detectAnalyzerQueryType("192.0.0.8"), "unknown");
  assert.equal(detectAnalyzerQueryType("192.88.99.1"), "unknown");
  assert.deepEqual(
    extractIocsFromText("192.0.0.8 192.0.0.9 192.0.0.10 192.88.99.1"),
    ["192.0.0.9", "192.0.0.10"],
  );
});

test("accepts public IPv6 inputs and excludes non-global IPv6 ranges", () => {
  const publicAddresses = [
    "2001:4860:4860::8888",
    "2606:4700:4700:0000:0000:0000:0000:1111",
  ];
  const nonPublicAddresses = [
    "::",
    "::1",
    "fc00::1",
    "fd12:3456:789a::1",
    "fe80::1",
    "ff02::1",
    "2001:db8::1",
    "4000::1",
    "2001:4860:::8888",
  ];

  for (const address of publicAddresses) {
    assert.equal(detectAnalyzerQueryType(address), "ip", address);
  }
  for (const address of nonPublicAddresses) {
    assert.equal(detectAnalyzerQueryType(address), "unknown", address);
  }
  assert.deepEqual(
    extractIocsFromText([...publicAddresses, ...nonPublicAddresses].join("\n")),
    publicAddresses,
  );
});

test("classifies an HTTP URL with an IPv6 literal as a URL", () => {
  assert.equal(detectAnalyzerQueryType("https://[2001:4860:4860::8888]/dns-query"), "url");
});
