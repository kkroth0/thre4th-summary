// Microsoft Patch Tuesday (MSRC CVRF v3.0) -> presentation-ready summary.
// Pure transforms only: no network, no cache. server/index.js owns fetching.

const SEVERITY_RANK = { Critical: 4, Important: 3, Moderate: 2, Low: 1 };

// Microsoft publishes a preliminary "<Month> Early Security Updates" document
// under the SAME id as the real Patch Tuesday (e.g. 2026-Jul), then replaces it
// in place on release day. It must never be shown as the month's patch set: it
// is a partial draft (July 2026 shipped 578 CVEs as "Early" vs 1150 for real,
// hiding both exploited zero-days).
const isEarlyDoc = (title) => /\bEarly\b/i.test(title || '');

// Two streams in a CVRF document are upstream code Microsoft republishes, not
// bugs it fixed in its own products. Neither belongs in the headline count —
// that is why the portals report ~420 for a month whose document holds 751.
//
//   Edge/Chromium — Google Chrome CVEs restated. 922 of July 2026's entries.
//   Azure Linux (CBL-Mariner) — the distro's OSS package stream (kernel, clamav,
//   perl, ...). 331 of August 2026's 751 entries, and zero Chromium that month,
//   so the title-only test used to let every one of them through.
// Neither stream is reliably identifiable from the title alone, so both tests
// fall back to the affected products.

// An MSRC-authored title always leads with the product ("Windows ... Vulnerability").
// A title that leads with a CVE id is carrying the upstream project's own bug
// description instead — empty, the bare id, or the id plus Chrome's wording
// ("CVE-2026-19137 Use after free in WebGL"). All three mean MSRC wrote nothing
// of its own about this entry.
const isUndescribed = (title) => !title || /^CVE-\d{4}-\d+\b/i.test(title.trim());

// The distro package stream ships under two naming shapes in the same document:
// "azl3 <pkg> <ver> on Azure Linux 3.0" and the bare "cbl2 <pkg> <ver>", which
// carries no distro name at all. Matching only the distro text missed 319 of
// April 2026's 737 entries, every one of them a CBL-Mariner 2.0 package.
const isDistroPackage = (name) => /^(azl|cbl)\d+\s/i.test(name) || /azure linux|cbl-mariner/i.test(name);
const isAzureLinuxVuln = (productNames) => productNames.length > 0 && productNames.every(isDistroPackage);

// Chrome CVEs restated for Edge. "Microsoft Edge for Android" bugs are Microsoft's
// own code and keep counting — only an entry with no description of its own, on
// nothing but Chromium-based Edge, is a restatement.
const isChromiumVuln = (title, productNames = []) =>
    /chromium/i.test(title || '') ||
    (isUndescribed(title) && productNames.length > 0 && productNames.every(n => /chromium/i.test(n)));

const isUpstreamVuln = (title, productNames) => isChromiumVuln(title, productNames) || isAzureLinuxVuln(productNames);

const stripHtml = (str) => (str || '').replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();

// Classify a vulnerability into a single product family using its title + affected product names
const classifyFamily = (title, productNames) => {
    const hay = `${title || ''} ${productNames.join(' ')}`.toLowerCase();
    if (/azure|microsoft entra|defender for/.test(hay)) return 'Azure & Cloud';
    if (/sharepoint/.test(hay)) return 'SharePoint';
    if (/exchange/.test(hay)) return 'Exchange Server';
    if (/sql server/.test(hay)) return 'SQL Server';
    if (/\.net|visual studio|asp\.net|nuget|powershell/.test(hay)) return 'Developer Tools & .NET';
    if (/office|word|excel|powerpoint|outlook|visio|onenote|\baccess\b|publisher/.test(hay)) return 'Microsoft Office';
    if (/\bedge\b|chromium/.test(hay)) return 'Microsoft Edge';
    if (/dynamics/.test(hay)) return 'Dynamics 365';
    if (/system center/.test(hay)) return 'System Center';
    if (/windows|win32|kernel|hyper-v|\brdp\b|smb|\bdns\b|tcp\/ip|active directory/.test(hay)) return 'Windows';
    return 'Other Microsoft Products';
};

const parseExploitStatus = (str) => {
    const s = str || '';
    const m = (re) => (s.match(re)?.[1] || '').trim();
    return {
        exploited: /Exploited:\s*Yes/i.test(s),
        publiclyDisclosed: /Publicly Disclosed:\s*Yes/i.test(s),
        exploitability: m(/Latest Software Release:\s*([^;]+)/i) || 'N/A'
    };
};

// Transform a raw CVRF document into a compact, presentation-ready summary
const normalizeCvrf = (doc) => {
    const productNameById = {};
    for (const p of (doc.ProductTree?.FullProductName || [])) {
        productNameById[p.ProductID] = p.Value;
    }

    const totals = { total: 0, critical: 0, important: 0, moderate: 0, low: 0, unknown: 0, exploited: 0, disclosed: 0, exploitMoreLikely: 0, upstream: 0 };
    const byImpact = {};
    const byFamily = {};
    const vulnerabilities = [];

    for (const v of (doc.Vulnerability || [])) {
        if (!v.CVE) continue;
        const threats = v.Threats || [];

        const affectedIds = (v.ProductStatuses || []).find(s => s.Type === 3)?.ProductID || [];
        const productNames = affectedIds.map(id => productNameById[id]).filter(Boolean);
        const upstream = isUpstreamVuln(v.Title?.Value, productNames);

        // Highest severity across products (Threat Type 3)
        let severity = null, sevRank = 0;
        for (const t of threats) {
            if (t.Type !== 3) continue;
            const val = t.Description?.Value;
            if (val && SEVERITY_RANK[val] && SEVERITY_RANK[val] > sevRank) { severity = val; sevRank = SEVERITY_RANK[val]; }
        }

        // Impact / vulnerability category (Threat Type 0)
        const impact = threats.find(t => t.Type === 0 && t.Description?.Value)?.Description?.Value || 'Other';

        // Exploit status (Threat Type 1)
        const ex = parseExploitStatus(threats.find(t => t.Type === 1)?.Description?.Value);

        // Highest CVSS base score + its vector
        let cvss = 0, vector = '';
        for (const c of (v.CVSSScoreSets || [])) {
            if ((c.BaseScore || 0) > cvss) { cvss = c.BaseScore; vector = c.Vector || ''; }
        }

        const family = classifyFamily(v.Title?.Value, productNames);

        // KB / vendor fixes (Remediation Type 2)
        const kbSet = new Map();
        for (const r of (v.Remediations || [])) {
            if (r.Type === 2 && r.Description?.Value) {
                kbSet.set(r.Description.Value, r.URL || `https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB${r.Description.Value}`);
            }
        }

        const description = stripHtml((v.Notes || []).find(n => n.Type === 2)?.Value).slice(0, 600);
        const cwe = Array.isArray(v.CWE) ? (v.CWE[0]?.Value || '') : (v.CWE?.Value || '');

        // Tallies. Upstream republications are counted on their own line only, so
        // every headline number below describes Microsoft's own patch set.
        if (upstream) {
            totals.upstream++;
        } else {
            totals.total++;
            if (severity === 'Critical') totals.critical++;
            else if (severity === 'Important') totals.important++;
            else if (severity === 'Moderate') totals.moderate++;
            else if (severity === 'Low') totals.low++;
            else totals.unknown++;
            if (ex.exploited) totals.exploited++;
            if (ex.publiclyDisclosed) totals.disclosed++;
            if (/More Likely/i.test(ex.exploitability)) totals.exploitMoreLikely++;
            byImpact[impact] = (byImpact[impact] || 0) + 1;
            byFamily[family] = (byFamily[family] || 0) + 1;
        }

        vulnerabilities.push({
            upstream,
            cve: v.CVE,
            title: v.Title?.Value || '',
            description,
            cwe,
            severity: severity || 'Unknown',
            impact,
            cvss: cvss || null,
            vector,
            exploited: ex.exploited,
            publiclyDisclosed: ex.publiclyDisclosed,
            exploitability: ex.exploitability,
            family,
            productCount: affectedIds.length,
            kbs: [...kbSet.entries()].map(([kb, url]) => ({ kb, url })),
            releaseDate: v.ReleaseDate || null
        });
    }

    // Sort by exploited, then disclosed, then CVSS desc. Upstream republications
    // sink below everything else so topCves stays Microsoft's own signal.
    vulnerabilities.sort((a, b) =>
        (a.upstream - b.upstream) ||
        (b.exploited - a.exploited) ||
        (b.publiclyDisclosed - a.publiclyDisclosed) ||
        ((b.cvss || 0) - (a.cvss || 0))
    );

    const sortEntries = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count }));

    return {
        id: doc.DocumentTracking?.Identification?.ID?.Value || '',
        title: doc.DocumentTitle?.Value || '',
        initialReleaseDate: doc.DocumentTracking?.InitialReleaseDate || null,
        currentReleaseDate: doc.DocumentTracking?.CurrentReleaseDate || null,
        totals,
        byImpact: sortEntries(byImpact),
        byFamily: sortEntries(byFamily),
        topCves: vulnerabilities.slice(0, 12),
        vulnerabilities
    };
};

export { SEVERITY_RANK, isEarlyDoc, isChromiumVuln, isAzureLinuxVuln, isUpstreamVuln, classifyFamily, parseExploitStatus, normalizeCvrf };
