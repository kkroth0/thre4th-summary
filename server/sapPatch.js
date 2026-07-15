// SAP Security Patch Day -> presentation-ready summary.
// Pure transforms only: no network, no cache. server/index.js owns fetching.
//
// SAP publishes monthly "Security Notes News" as a public HTML table at
//   https://support.sap.com/en/my-support/knowledge-base/security-notes-news/{month}-{year}.html
// Patch Day is the second Tuesday of the month. There is no API/feed, so we
// scrape the static table (Note# | Title | Priority | CVSS).
import * as cheerio from 'cheerio';

// Hot News is SAP's historical top tier; recent pages label it "Critical".
// Treat them as the same rank so KPIs/sorting are stable either way.
export const PRIORITY_RANK = { 'Hot News': 4, Critical: 4, High: 3, Medium: 2, Low: 1 };

const MONTHS = ['january', 'february', 'march', 'april', 'may', 'june',
    'july', 'august', 'september', 'october', 'november', 'december'];

// Second Tuesday (SAP Patch Day) of a given year/month (0-based month), UTC.
const secondTuesday = (year, month) => {
    const firstDow = new Date(Date.UTC(year, month, 1)).getUTCDay(); // 0=Sun..6=Sat
    const firstTue = 1 + ((2 - firstDow + 7) % 7);
    return new Date(Date.UTC(year, month, firstTue + 7));
};

// The latest published SAP Patch Day relative to `now`: the current month once
// its second Tuesday has passed, otherwise the previous month.
export const latestPatchMonth = (now = new Date()) => {
    let year = now.getUTCFullYear();
    let month = now.getUTCMonth();
    if (now < secondTuesday(year, month)) {
        month -= 1;
        if (month < 0) { month = 11; year -= 1; }
    }
    return { year, month, monthName: MONTHS[month], url: monthUrl(year, month) };
};

export const monthUrl = (year, month) =>
    `https://support.sap.com/en/my-support/knowledge-base/security-notes-news/${MONTHS[month]}-${year}.html`;

const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
const normalizeNoteUrl = (href, note) => {
    if (!href) return `https://me.sap.com/notes/${note}`;
    try {
        return new URL(href, 'https://me.sap.com').href;
    } catch {
        return `https://me.sap.com/notes/${note}`;
    }
};

// "On 14th of July 2026, SAP security patch day ..." -> ISO date (or null).
const parseReleaseDate = (text) => {
    const m = /\bOn\s+(\d{1,2})(?:st|nd|rd|th)?\s+of\s+([A-Za-z]+)\s+(\d{4})/i.exec(text || '');
    if (!m) return null;
    const month = MONTHS.indexOf(m[2].toLowerCase());
    if (month < 0) return null;
    return new Date(Date.UTC(Number(m[3]), month, Number(m[1]))).toISOString().slice(0, 10);
};

// Parse the SAP Security Notes page. Tolerant of layout drift: skips malformed
// rows, never throws, returns whatever valid notes it finds.
export function parseSapNotes(html) {
    const $ = cheerio.load(html || '');

    // The notes table is the one whose header row names Note# and CVSS.
    let table = null;
    $('table').each((_, el) => {
        if (table) return;
        const head = clean($(el).find('tr').first().text()).toLowerCase();
        if (head.includes('note#') && head.includes('cvss')) table = $(el);
    });

    const notes = [];
    if (table) {
        table.find('tr').each((_, tr) => {
            const cells = $(tr).find('td, th');
            if (cells.length < 4) return;
            const noteLink = $(cells[0]).find('a[href*="/notes/"], a[href*="me.sap.com"]').first();
            const note = clean(noteLink.text()) || clean($(cells[0]).text());
            if (!/^\d{6,}$/.test(note)) return; // header/non-note rows

            const titleCell = $(cells[1]);
            const titleText = clean(titleCell.text());
            const cves = [...new Set((titleText.match(CVE_RE) || []).map((c) => c.toUpperCase()))];
            // Drop the leading "[CVE-...][CVE-...]" prefix for a clean title.
            const title = titleText.replace(/^(\[\s*CVE-\d{4}-\d{4,}\s*\]\s*)+/i, '').trim() || titleText;

            const cvssLink = $(cells[3]).find('a').first();
            const cvssText = clean(cvssLink.text()) || clean($(cells[3]).text());
            const cvss = /^\d{1,2}(\.\d)?$/.test(cvssText) ? Number(cvssText) : null;
            const vectorMatch = /CVSS:[^"']*/i.exec(cvssLink.attr('href') || '');

            notes.push({
                note,
                noteUrl: normalizeNoteUrl(noteLink.attr('href'), note),
                title,
                cves,
                priority: clean($(cells[2]).text()) || 'N/A',
                cvss,
                cvssVector: vectorMatch ? vectorMatch[0] : null,
                isUpdate: /update to security note/i.test(titleText),
            });
        });
    }

    return { releaseDate: parseReleaseDate($('body').text()), notes };
}

// Sort by priority rank (desc) then CVSS (desc); stable for equal keys.
export const sortNotes = (notes) => [...notes].sort((a, b) =>
    (PRIORITY_RANK[b.priority] || 0) - (PRIORITY_RANK[a.priority] || 0)
    || (b.cvss || 0) - (a.cvss || 0));

export function summarize(notes) {
    const byPriority = {};
    let maxCvss = 0;
    const cves = new Set();
    for (const n of notes) {
        byPriority[n.priority] = (byPriority[n.priority] || 0) + 1;
        if (typeof n.cvss === 'number') maxCvss = Math.max(maxCvss, n.cvss);
        for (const c of n.cves) cves.add(c);
    }
    return {
        total: notes.length,
        byPriority,
        hotNews: (byPriority['Hot News'] || 0) + (byPriority.Critical || 0),
        high: byPriority.High || 0,
        maxCvss,
        cveCount: cves.size,
    };
}
