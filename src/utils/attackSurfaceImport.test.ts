import test from "node:test";
import assert from "node:assert/strict";
import {
  parseAttackSurfaceTargets,
  targetToMonitorDraft,
} from "./attackSurfaceImport.ts";

test("parses supported attack surface targets from TXT content", () => {
  const result = parseAttackSurfaceTargets([
    "# customer perimeter",
    "8.8.8.8",
    "8.8.4.0/24",
    "Example.COM",
    "AS15169",
    "15170",
    "shodan: org:\"Example\" port:3389",
    "query: ssl.cert.subject.cn:example.com",
    "not a target",
  ].join("\n"));

  assert.deepEqual(
    result.targets.map(({ kind, value, label }) => [kind, value, label]),
    [
      ["ip", "8.8.8.8", "8.8.8.8"],
      ["cidr", "8.8.4.0/24", "8.8.4.0/24"],
      ["domain", "example.com", "example.com"],
      ["asn", "AS15169", "AS15169"],
      ["asn", "AS15170", "AS15170"],
      ["shodan_query", "org:\"Example\" port:3389", "Shodan query"],
      ["shodan_query", "ssl.cert.subject.cn:example.com", "Shodan query"],
    ],
  );
  assert.equal(result.ignored, 2);
});

test("deduplicates normalized targets while keeping first occurrence order", () => {
  const result = parseAttackSurfaceTargets("Example.COM\nexample.com\nAS15169\n15169\n");

  assert.deepEqual(
    result.targets.map(({ kind, value }) => [kind, value]),
    [
      ["domain", "example.com"],
      ["asn", "AS15169"],
    ],
  );
  assert.equal(result.ignored, 0);
});

test("parses targets from a JSON array of strings", () => {
  const result = parseAttackSurfaceTargets(
    JSON.stringify(["8.8.8.8", "Example.COM", "8.8.4.0/24"]),
  );

  assert.deepEqual(
    result.targets.map(({ kind, value }) => [kind, value]),
    [
      ["ip", "8.8.8.8"],
      ["domain", "example.com"],
      ["cidr", "8.8.4.0/24"],
    ],
  );
  assert.equal(result.ignored, 0);
});

test("parses targets from a JSON array of objects with common fields", () => {
  const result = parseAttackSurfaceTargets(
    JSON.stringify([
      { value: "8.8.8.8" },
      { ip: "1.1.1.1" },
      { target: "example.com" },
      { query: "org:\"Example\" port:3389" },
      { note: "no usable field" },
    ]),
  );

  assert.deepEqual(
    result.targets.map(({ kind, value }) => [kind, value]),
    [
      ["ip", "8.8.8.8"],
      ["ip", "1.1.1.1"],
      ["domain", "example.com"],
      ["shodan_query", "org:\"Example\" port:3389"],
    ],
  );
  assert.equal(result.ignored, 1);
});

test("parses targets from a JSON object exposing a targets array", () => {
  const result = parseAttackSurfaceTargets(
    JSON.stringify({ targets: ["8.8.8.8", "9.9.9.9"] }),
  );

  assert.deepEqual(result.targets.map(({ value }) => value), ["8.8.8.8", "9.9.9.9"]);
});

test("deduplicates targets parsed from JSON", () => {
  const result = parseAttackSurfaceTargets(JSON.stringify(["Example.com", "example.COM"]));

  assert.deepEqual(result.targets.map(({ value }) => value), ["example.com"]);
});

test("falls back to line parsing when JSON is malformed", () => {
  const result = parseAttackSurfaceTargets("[\n8.8.8.8\n]");

  assert.deepEqual(result.targets.map(({ value }) => value), ["8.8.8.8"]);
});

test("converts imported targets to monitor drafts", () => {
  const [target] = parseAttackSurfaceTargets("query: org:\"Example\"").targets;

  assert.deepEqual(targetToMonitorDraft(target), {
    type: "shodan_query",
    value: "org:\"Example\"",
    label: "Shodan query",
  });
});
