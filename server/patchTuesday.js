// Microsoft Patch Tuesday (MSRC CVRF v3.0) -> presentation-ready summary.
// Pure transforms only: no network, no cache. server/index.js owns fetching.

const SEVERITY_RANK = { Critical: 4, Important: 3, Moderate: 2, Low: 1 };

// Microsoft publishes a preliminary "<Month> Early Security Updates" document
// under the SAME id as the real Patch Tuesday (e.g. 2026-Jul), then replaces it
// in place on release day. It must never be shown as the month's patch set: it
// is a partial draft (July 2026 shipped 578 CVEs as "Early" vs 1150 for real,
// hiding both exploited zero-days).
const isEarlyDoc = (title) => /\bEarly\b/i.test(title || '');

// Edge/Chromium entries are Google Chrome CVEs that Microsoft merely restates.
// They are 40% of a typical document and carry no MSRC severity (427 of 467 in
// July 2026), so folding them into the headline counts inflates the total and
// manufactures a large "Unknown" bucket. Counted separately instead.
const isChromiumVuln = (title) => /chromium/i.test(title || '');

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

    const totals = { total: 0, critical: 0, important: 0, moderate: 0, low: 0, unknown: 0, exploited: 0, disclosed: 0, exploitMoreLikely: 0, chromium: 0 };
    const byImpact = {};
    const byFamily = {};
    const vulnerabilities = [];

    for (const v of (doc.Vulnerability || [])) {
        if (!v.CVE) continue;
        const threats = v.Threats || [];
        const chromium = isChromiumVuln(v.Title?.Value);

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

        const affectedIds = (v.ProductStatuses || []).find(s => s.Type === 3)?.ProductID || [];
        const productNames = affectedIds.map(id => productNameById[id]).filter(Boolean);
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

        // Tallies. Chromium restatements are counted on their own line only, so
        // every headline number below describes Microsoft's own patch set.
        if (chromium) {
            totals.chromium++;
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
            chromium,
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

    // Sort by exploited, then disclosed, then CVSS desc. Chromium restatements
    // sink below everything else so topCves stays Microsoft's own signal.
    vulnerabilities.sort((a, b) =>
        (a.chromium - b.chromium) ||
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

export { SEVERITY_RANK, isEarlyDoc, isChromiumVuln, classifyFamily, parseExploitStatus, normalizeCvrf };
