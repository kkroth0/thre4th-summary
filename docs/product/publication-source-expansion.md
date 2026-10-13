# Publication source expansion

The user's Hunt snapshot contained 200 publisher domains. The former catalog had 93 collection entries and corresponded to 35 of those domains. `server/publicationSources.json` registers the remaining 165 channels individually, including author subdomains and portals that differ from already-monitored channels. This does not re-enable removed enrichment APIs: Team Cymru, OPSWAT and Pulsedive are publication sources here.

Automatic channels prefer RSS/Atom, discover advertised alternate feeds and use publication cards or NewsArticle/BlogPosting JSON-LD when RSS is unavailable. Cached channel URLs, HTTP validators, inferred first-seen dates and the rolling publication snapshot survive refreshes. A failed provider preserves its prior items with stale status; empty/unrecognizable HTML and WAF responses are errors, not successful empty feeds. Discovery stays within the publisher and explicitly allowed RSS transports. Each request validates and pins public DNS records and checks redirects individually.

The source panel supports domain/name search, per-channel RSS/HTML provenance, pending/collecting/fresh/stale/error states and fifteen-second health updates while open. Enabled configuration is labelled separately from successful collection. The cache budget scales with the expanded catalog.

## OT/ICS

Existing Industrial Cyber, CISA ICS and Team82/Nozomi collectors are retained. Added channels:

- SecurityWeek ICS/OT category RSS.
- CISA news filtered by the supplied OT topic.
- Claroty Team82 BR research and white-paper listings, with distinct path scopes.
- Claroty disclosure-dashboard RSS (the dashboard page and feed are the same channel).
- Siemens ProductCERT advisories and alerts, using the official Atom feeds linked from https://productcert.siemens.com/ rather than a tracked SPA URL.

These channels carry trusted OT/ICS provenance into categorization, including generic white-paper titles that lack industrial keywords. Claroty/Team82, Nozomi Networks and Dragos are grouped under OT/ICS vendors; Siemens, Schneider Electric, Rockwell and other industrial vendors were already present. Vendor IDs remain stable.

The catalog now has 265 collection entries: 94 direct RSS/Atom, 168 automatic RSS/HTML and three existing scrapers. Registration does not guarantee provider availability; actual errors and item counts are exposed by authenticated GET `/api/feeds`.

## Validation

Tests cover source registration, publisher boundaries, RSS cache/304/outage behavior, real versus inferred dates, article-versus-navigation extraction, scoped OT listings, DNS pinning and redirect rejection. Live validation uses public sources without account credentials; results are documented separately from VPS health because network/provider policies may differ.
