import test from "node:test";
import assert from "node:assert/strict";
import { detectIOCType, fetchThreatData, fetchThreatDataProgressive, fetchAttackSurfaceCredits, formatVendorData, resolveVendorsForQuery } from "./threatApi";
import { refang } from "@/utils/defang";
import { isSupportedAnalyzerQuery } from "@/utils/iocExtract";

test('known absent VirusTotal and Shodan records are no-data responses while access errors remain failures',async()=>{
  const original=globalThis.fetch;
  try{
    globalThis.fetch=async()=>new Response(JSON.stringify({error:'Resource not found'}),{status:404});
    const empty=await fetchThreatDataProgressive('46.101.130.1',['VirusTotal','Shodan'],()=>{},{includeRaw:true});
    assert.ok(empty.vendorData.every(row=>!row.error&&row.data.Status==='No data'&&(row.rawPayload as {queryStatus?:string})?.queryStatus==='not_found'));
    globalThis.fetch=async()=>new Response(JSON.stringify({error:'Forbidden'}),{status:403});
    const denied=await fetchThreatData('46.101.130.1',['Shodan']);assert.ok(denied.vendorData[0].error);
  }finally{globalThis.fetch=original;}
});

test("detects a public IPv6 address as IP and an IPv6 literal URL as URL", () => {
  assert.equal(detectIOCType("2606:4700:4700::1111"), "ip");
  assert.equal(detectIOCType("https://[2606:4700:4700::1111]/status"), "url");
});

test('bulk lookup retains the full payload without adding raw retention to normal scans', async () => {
  const original = globalThis.fetch;
  const payload = { data: { ip_str: '46.101.130.1', ports: [443], extra: { nested: ['complete-response'] }, data: [] } };
  globalThis.fetch = async () => new Response(JSON.stringify(payload));
  try {
    const normal = await fetchThreatData('46.101.130.1', ['Shodan']);
    const bulk = await fetchThreatDataProgressive('46.101.130.1', ['Shodan'], () => {}, { includeRaw: true });
    assert.equal(normal.vendorData[0].rawPayload, undefined);
    assert.deepEqual(bulk.vendorData[0].rawPayload, payload);
  } finally { globalThis.fetch = original; }
});

test('manual enrichment refresh requests fresh data; normal lookups permit cached responses', async () => {
  const previous = globalThis.fetch;
  const bodies: { query: string; fresh?: boolean }[] = [];
  globalThis.fetch = async (_input, options) => {
    bodies.push(JSON.parse(String(options?.body)));
    return new Response(JSON.stringify({ data: { ip_str: '9.9.9.10', ports: [], data: [] } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    await fetchThreatData('9.9.9.10', ['Shodan']);
    let completed = 0;
    await fetchThreatDataProgressive('9.9.9.10', ['Shodan'], () => { completed++; }, { fresh: true });
    assert.deepEqual(bodies, [{ query: '9.9.9.10' }, { query: '9.9.9.10', fresh: true }]);
    assert.equal(completed, 1);
  } finally { globalThis.fetch = previous; }
});

test("routes IPv6 only to providers backed by IPv6-capable endpoints", () => {
  const selected = [
    "IP Geolocation", "VirusTotal", "AbuseIPDB", "AlienVault OTX", "Shodan",
    "ThreatFox",
  ];

  assert.deepEqual(resolveVendorsForQuery("2606:4700:4700::1111", selected), [
    "IP Geolocation", "VirusTotal", "AbuseIPDB", "Shodan", "ThreatFox",
  ]);
});

test("refanged input makes defanged IOCs searchable", () => {
  // Before the refang, each of these was rejected as "unknown" and aborted the scan.
  assert.equal(isSupportedAnalyzerQuery(refang("evil[.]com")), true);
  assert.equal(isSupportedAnalyzerQuery(refang("1.2.3[.]4")), true);
  assert.equal(isSupportedAnalyzerQuery(refang("hxxps://bad[.]com/x")), true);
});

test("OpenPhish exposes a capital-S Status the aggregator can count", () => {
  assert.equal(formatVendorData("OpenPhish", { listed: true, status: "Listed as phishing" }, "http://x").Status, "Phishing");
  assert.equal(formatVendorData("OpenPhish", { listed: false, status: "x" }, "http://x").Status, "Clean");

});

test("loads Shodan credits without exposing account data", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ plan: "member", queryCredits: 99 }));

  try {
    assert.deepEqual(await fetchAttackSurfaceCredits(), { plan: "member", queryCredits: 99 });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('missing PhishStats results and unverified PhishTank reports do not become malicious or clean votes', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (path) => new Response(JSON.stringify(String(path).endsWith('/phishstats') ? [] : {results:{in_database:true,verified:false,valid:false}}));
  try { const result = await fetchThreatData('https://example.com/', ['PhishStats','PhishTank']); assert.equal(result.detections,0); assert.equal(result.reportingVendors,0); assert.equal(result.threatLevel,'unknown'); }
  finally { globalThis.fetch = original; }
});

test('URLhaus URL results expose all payload families and tags without becoming a clean vote', () => {
  const result = formatVendorData('URLhaus', {query_status:'ok',id:'123',url:'https://evil.example.org/a',tags:['Vidar'],payloads:[{signature:'Vidar'},{signature:'Stealc'}]}, 'https://evil.example.org/a');
  assert.equal(result.Status,'Malicious URLs Found');
  assert.equal(result['URL Count'],1);
  assert.deepEqual(result['All Malware'],['Vidar','Stealc']);
  assert.deepEqual(result.Tags,['Vidar']);
  assert.equal(formatVendorData('URLhaus',{query_status:'ok'},'evil.example.org').Status,'No data');
  assert.deepEqual(resolveVendorsForQuery('46.101.130.1',['URLhaus']),['URLhaus']);
});

test('retry incomplete retains successful sources and only requests failed sources', async () => {
  const original = globalThis.fetch;
  const calls: string[] = [];
  const previous = { query: '8.8.8.8', overallScore: 0, threatLevel: 'unknown' as const, totalVendors: 2, detections: 0,
    vendorData: [{ name: 'VirusTotal', data: { Status: 'Clean', Malicious: 0 }, rawPayload: { retained: true } },
      { name: 'AbuseIPDB', data: {}, error: 'Fonte aguardando disponibilidade.' }] };
  globalThis.fetch = async path => { calls.push(String(path)); return new Response(JSON.stringify({ data: { data: { ipAddress: '8.8.8.8', abuseConfidenceScore: 0 } } })); };
  try {
    const result = await fetchThreatDataProgressive('8.8.8.8', ['VirusTotal', 'AbuseIPDB'], () => {}, { previous });
    assert.deepEqual(calls, ['/api/abuseipdb']);
    assert.deepEqual(result.vendorData.find(v => v.name === 'VirusTotal')?.rawPayload, { retained: true });
    assert.ok(result.vendorData.every(v => !v.error));
  } finally { globalThis.fetch = original; }
});

