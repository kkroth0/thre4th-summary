# Product performance: first optimization pass

Production diagnosis found bulletin deliveries timing out while synchronous news correlation blocked the API. One observed correlation cycle took 106,415 ms. Extraction and correlation now yield between batches; historic CVE queries run in a bounded read-only worker. The two recent failed bulletins were regenerated through the authenticated existing worker and delivered JSON, PPTX and PDF.

Historical CVE queries load descriptions, references and exploit counts only for the requested page. Summary/ranking/lookup/vendor and EPSS covering indexes are built by a separate worker before scheduled imports continue; the API can start and handle unrelated requests during migration. These additive indexes do not alter imported records. The reader has a bounded 64 MB SQLite cache. Locally, an overview over 78,798 real imported records completed in 301 ms; this is a local measurement, not a VPS latency guarantee.

Passive enrichment lookups coalesce identical concurrent requests and cache successful JSON for five minutes, scoped to account and credential fingerprint. The cache covers VirusTotal, AbuseIPDB IP/block, OTX, Shodan, URLhaus, MalwareBazaar, ThreatFox, PhishTank and IP geolocation. It is limited to 16 MB / 1,000 entries and 128 concurrent unique lookups. Errors and invalid authentication results are not cached. Existing provider throttles and key rotation remain in place. WHOIS and phishing feeds retain their provider-specific cache durations.

Explicit enrichment/CIDR refresh requests bypass saved responses. WHOIS, PhishStats and OpenPhish also honor explicit refresh. Response headers expose whether a lookup was fresh, cached or shared and when it was collected. Only administrators can read aggregate hit/miss/shared/error/memory counters at `/api/admin/performance`; queries and credentials are never included.

The concurrency test runs 50 identical simultaneous lookups against a controlled upstream and verifies exactly one upstream call. This demonstrates duplicate suppression; it does not claim a measured production credit-saving percentage.

CVE import polling now runs every 30 seconds for the active view, with the overview poll disabled during listing views. Monitoring preferences and the intelligence overview reuse browser query data for one minute. Progressive enrichment clears completed timeout timers. Account-scoped caches and explicit user refresh are preserved.

Further optimization should be driven by production latency, cache hit rate, provider failures and credit usage. This pass addresses observed contention and duplicate work; it does not claim every feature has been optimized.

Production validation on 2026-10-13 confirmed a cache miss followed by a cache hit for the same passive IP lookup, preserving the original collection timestamp. The complete catalog reported 386,726 CVEs, all 25 annual datasets imported and NVD/KEV/EPSS/GitHub ready. An overview request completed in 5.97 seconds, then a warm request in 2.10 seconds (end-to-end HTTP, including network latency). Weaponized initially took 9.16 seconds; its queries now start from the small KEV subset instead of scanning the full corpus. Planner statistics are refreshed after migration, with a persistent checkpoint to avoid repeating index preparation on every deploy.
