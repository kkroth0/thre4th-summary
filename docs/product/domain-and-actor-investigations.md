# Domain and actor investigation views

Domain and HTTP(S) URL queries open a hostname investigation workspace. The full
URL remains the reputation target in **Risks and sources**. IP URLs and CIDRs
keep their existing workflows.

## Domain sources

- Current DNS: the existing resolver, with successful nonempty observations
  persisted in `server/.domain-dns-history.json`. Maximum 2,000 hosts and 100
  record changes per host. Repeated record sets update the observation window;
  this is not a claim of continuous uptime or earlier passive DNS coverage.
- WHOIS: existing Who.is snapshot lookup and configured server credential.
- Subdomains: `https://crt.name/v1/search?apex=...&format=json&dates=1`.
  Registrable domain uses the Public Suffix List. Requests share a 24h cache per
  apex, respecting the source's 100 requests/IP/day allowance. Responses are
  capped at 20,000 names; names are filtered to the exact target or its children.
  First seen is an upstream observation, not domain creation or live resolution.
  crt.name does not provide certificate metadata.
- Certificates: passive `https://crt.sh/?q=...&output=json`, deduplicated by
  certificate ID, with SANs, issuer, validity and CT reference. 1h cache; at most
  1,000 records. No direct TLS probing or certificate download.
- External DNS history: Who.is `/v1/dns/{domain}/changes`, 100 results per page;
  opaque next cursor is passed unchanged. Pages load only on user action (up to
  10 pages per view). The current account returned `403 plan_required`; local
  observations remain visible and explicitly labeled. No paid live refresh or
  200-credit WHOIS snapshot-history endpoint is used.
- DNSHistory.org: direct source and subdomain page 1/2 links. Automated access
  returned a browser challenge, so no scraper or challenge bypass is enabled.

Provider failures remain distinct from valid empty results. Requests have bounded
timeouts, response sizes, caches and single-flight handling. Credential-specific
history caches include a non-reversible fingerprint. Private results use owner
query keys and `Cache-Control: private, no-store`.

## Actor evidence

Overview, listing and global views derive metrics from the actual catalog and
news archive. Countries normalize common names and ISO codes before counting.
Unknown origins do not appear as a geographic attribution. Motivations remain
motivations, rather than being presented as confirmed incident counts.

Actor profiles have AKA, period selection, and IP, host, SHA256 and publication
tabs, plus ATT&CK, software, metadata and references. Default period: 180 days;
30/90/365 days and the entire archive are explicit options. Indicators are unique
per type/value; each retains publication-level evidence. Source actor attribution
is required, never inherited from another source in the same event. A publication
co-occurrence is not ownership, DNS resolution or a verified C2 relationship.

14 actor artwork assets came from the Hunt HTML files the user supplied, including
ShinyHunters and Lazarus. `server/data/actor-logos.json` records each reference file
and its source; originals remain in Downloads. Assets are served locally under
`public/images/actors/`. SVGs containing scripts, external resource references,
event handlers or foreign objects were excluded. No Hunt branding/account photos
were imported. Unknown artwork falls back to initials. Several Ransomware.live
image references returned HTML or placeholder images, so these were not shipped
as working logos.

## Feed changes

CVEs and malware have independent table columns. The Artificial Intelligence
navigation bucket recognizes explicit AI, LLM, generative AI and model security
terms, including collected article bodies. Ambiguous body acronyms and unqualified
Claude/Gemini names do not match. It remains compatible with overlapping threat
categories. Extraction version `feed-v7` refreshes persisted feed classifications.
