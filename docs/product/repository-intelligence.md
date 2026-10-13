# Repository intelligence and bulletin extraction

Two built-in, independently switchable GitHub sources complement editorial feeds:

- Palo Alto Networks Unit42 Timely Threat Intel: dated TXT/Markdown reports.
- Arctic Wolf wolf-tools: text/CSV reports within threat-intelligence only.

The collector pins text files to a commit, checks the repository head hourly using ETags, caches completed report fingerprints, and advances at most two reports per source per collection cycle. It never retrieves or runs malware payloads, policy binaries or detection scripts. A cold start backfills gradually. Unit42 retains its latest 30 days; Arctic Wolf includes historical reports using the actual last commit date, explicitly recorded as such. Historical intelligence is never assigned today's publication date.

IOC extraction scans complete supported text, including trailing lists. CSV parsing selects indicator columns rather than treating article references or explanatory notes as indicators. Unit42 IOC sections exclude lines explicitly identifying legitimate services. Host paths and behavioural strings remain report context, not IP/domain/hash values. Repository revision and file references persist in the news archive.

Live validation on 2026-10-13 returned all 32 SHA-256 hashes (25 agents, 7 stagers), two malicious domains and two URLs for the C2Agent report. The legitimate Firecrawl MCP service remains in the report text, outside malicious indicator counts. The regression fixture is the indicator section supplied by the user. The shared domain extractor now accepts mixed dots such as agent.x90[.]dev without losing the leading label.

Bulletin jobs reuse server-collected bodies and IOCs; client requests cannot replace source text. The worker revalidates each public URL, consolidates all available sources into one document and performs one report analysis. It keeps appendix text outside the narrative model input. Cached IOC values are supplied independently from narrative text limits so late tables are not dropped. If attachment rendering exceeds the worker deadline after a valid JSON is complete, the extraction is delivered without unfinished attachments. Missing sources are excluded from evidence references rather than silently presented as collected.

Both the site and bd-ppt-generator-cti worker must be deployed for the new job payload to avoid rescraping. Verification retries an existing failed job using persisted collection content; it does not create a synthetic successful bulletin.

Production validation exposed a retention mismatch: historical Arctic Wolf reports were outside the 60-day event correlation window. Historical records now go directly to the permanent archive; only current records enter the live snapshot. A historical backfill cannot abort publication of the current feed. Read routes trigger cold collection in the background instead of waiting for every publisher. The previous v7 snapshot remains readable while v8 is refreshed.

Manual news enrichment now persists source-specific IOC/entity evidence into both the archive and event store, and updates the article cache and current snapshot. Supplemental appendix indicators survive subsequent unchanged-body refreshes. Actor profiles derive their activity from these persisted source records; a multi-source response's IOC union is never assigned to every mentioned actor. API provider reputation lookups remain an explicit investigation action, rather than an automatic bulk VirusTotal/AbuseIPDB call for every indicator in every news item.
