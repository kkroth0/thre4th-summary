# Primary Search Cleanup and Network Overview Design

## Objective

Keep the primary analyzer focused on IOC enrichment, eliminate integrations and visualizations that no longer add value, and make the most relevant network ownership and location facts immediately visible.

## Scope

### Primary search inputs

The primary analyzer accepts only:

- public IPv4 addresses;
- domains;
- HTTP/HTTPS URLs;
- MD5, SHA-1, and SHA-256 hashes.

CVE identifiers are no longer extracted from pasted text or uploaded files, accepted by the primary search validator, advertised in primary-search copy, or shown as primary-search examples. Dedicated CVE pages, dashboards, advisory processing, and CVE data endpoints remain unchanged.

ASN is not a search input. ASN remains an enrichment field returned for IP searches.

### Criminal IP removal

The Criminal IP integration is removed from the product rather than merely hidden when its API key is absent. Removal covers:

- backend route and provider configuration status;
- frontend fetcher, formatter, support map, and vendor map;
- default and saved vendor selection normalization;
- vendor filter, directory, settings, icons, external links, sorting, and report links;
- documentation and other product references that imply the integration is available.

Existing browser storage may still contain `Criminal IP`; the application must discard unsupported saved vendor names when restoring a selection.

## Result-page information hierarchy

For a single IOC result, the order is:

1. quick actions;
2. threat summary;
3. highlighted Geographic & Network Data overview;
4. IOC timeline;
5. provider results and remaining detailed analysis.

The existing Geolocation map card and the provider Top 10 threat-classification card are removed as obsolete. They are not relocated or replaced.

## Geographic & Network Data overview

The overview is a dedicated, responsive top-level panel rather than one card inside the old three-column chart group.

For IP results, it presents the available values in a scannable grid:

- ISP;
- Organization;
- Country;
- Region;
- City;
- ASN/AS;
- Network/CIDR.

Each fact has a short label, an appropriate icon, and a value with enough width to avoid unnecessary truncation. Network identifiers use monospaced text. The panel must work from one to seven populated facts, switching from one column on narrow screens to multiple columns on larger screens.

Values are composed from existing provider results with deterministic fallbacks. Empty, `Unknown`, `N/A`, and equivalent placeholder values are omitted. The whole panel is omitted when no useful geographic or network data exists, as is expected for many hash and URL searches.

The panel remains informational: it does not affect the threat score or verdict.

## Data sources and fallback rules

The overview reuses already-fetched data and does not add a network request. Preferred sources are:

- IP Geolocation for ISP, organization, country, region, and city;
- AbuseIPDB for ISP, country, ASN, and CIDR fallbacks;
- VirusTotal, Shodan, or Censys for network, organization, ASN, or location fallbacks when the preferred sources have no usable value.

The implementation centralizes placeholder filtering and field selection so the UI and exported report do not disagree about whether a value exists.

## Search verification

Automated tests cover the behavior that can be verified without live third-party credentials:

- free-text extraction includes IP, domain, URL, MD5, SHA-1, and SHA-256, but excludes CVE;
- client and server query-type detection agree for every supported input;
- malformed IPs, domains, URLs, and hashes are rejected;
- each supported input type routes only to compatible providers;
- Criminal IP never appears in restored selections or provider routing;
- Geographic & Network Data field composition honors source precedence and removes placeholders;
- the obsolete Geolocation and Top 10 panels are absent from the rendered result structure.

Live provider health depends on credentials, quotas, and upstream availability. Verification therefore separates local contract/routing tests from optional credentialed smoke checks. Any provider failure found during a live smoke check is reported by provider and input type instead of being treated as proof that all searches are broken.

## Error handling

One provider failure must not abort the complete IOC scan. Supported providers continue to return their existing per-provider error state. Unsupported input/provider combinations are filtered before a request is made.

The primary search shows a clear validation error for unsupported input, including CVE, and lists the accepted IOC types without suggesting ASN or CVE.

## Out of scope

- adding ASN as a search input;
- changing CVE dashboards, advisory feeds, or CVE enrichment outside the primary analyzer;
- replacing the removed map or Top 10 visualization;
- adding a new geolocation or threat-intelligence provider.
