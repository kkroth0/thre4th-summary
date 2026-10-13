const invalid = message => Object.assign(new Error(message), { status: 400 });
const names = values => (Array.isArray(values) ? values : []).map(value => typeof value === 'string' ? value : value?.name).filter(Boolean);

export function newsExportQuery(query = {}) {
    const boundary = (value, end) => {
        const text = String(value || '');
        const day = /^\d{4}-\d{2}-\d{2}$/.test(text);
        if (!day && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(text)) throw invalid('Informe as datas inicial e final.');
        const date = new Date(text);
        if (!Number.isFinite(date.getTime()) || (day ? date.toISOString().slice(0, 10) !== text : date.toISOString() !== text)) throw invalid('Data inválida.');
        return day && end ? new Date(date.getTime() + 86400000 - 1).toISOString() : date.toISOString();
    };
    const from = boundary(query.from, false), to = boundary(query.to, true);
    if (from > to) throw invalid('A data inicial deve preceder a final.');
    const dataset = String(query.dataset || 'news'), format = String(query.format || 'csv');
    if (!['news', 'iocs'].includes(dataset) || !['csv', 'json'].includes(format)) throw invalid('Formato de exportação inválido.');
    return { from, to, dataset, format };
}

export function newsExportRows(publications, dataset) {
    const rows = [];
    const seen = new Set();
    for (const publication of publications) {
        if (!publication?.link || seen.has(publication.link)) continue;
        seen.add(publication.link);
        const common = {
            title: publication.title || '', source: publication.source || '', url: publication.link,
            date: publication.pubDate || '', dateBasis: publication.dateInferred ? 'collected' : 'published',
            storyId: publication.storyId || '', categories: publication.categories || [], cves: publication.cves || [],
            actors: names(publication.actors), malware: names(publication.malware),
        };
        if (dataset === 'news') {
            rows.push({ ...common, ips: publication.iocs?.ips || [], domains: publication.iocs?.domains || [], hashes: publication.iocs?.hashes || [], urls: publication.iocs?.urls || [] });
        } else {
            for (const [field, type] of [['ips', 'ip'], ['domains', 'domain'], ['hashes', 'hash'], ['urls', 'url']]) {
                const values = Array.isArray(publication.iocs?.[field]) ? publication.iocs[field] : [];
                for (const value of new Set(values.filter(value => typeof value === 'string' && value.trim()).map(value => value.trim()))) rows.push({ type, indicator: value, ...common });
            }
        }
    }
    return rows;
}

export function newsExportCsv(rows, dataset) {
    const common = ['title', 'source', 'url', 'date', 'dateBasis', 'storyId', 'categories', 'cves', 'actors', 'malware'];
    const columns = dataset === 'news' ? [...common, 'ips', 'domains', 'hashes', 'urls'] : ['type', 'indicator', ...common];
    const cell = value => {
        const text = Array.isArray(value) ? value.join(' | ') : String(value ?? '');
        const safe = /^[\s\u0000-\u001f]*[=+@-]/.test(text) || /^[\t\r\n]/.test(text) ? "'" + text : text;
        return '"' + safe.replaceAll('"', '""') + '"';
    };
    return '\uFEFF' + [columns.map(cell).join(','), ...rows.map(row => columns.map(key => cell(row[key])).join(','))].join('\r\n') + '\r\n';
}
