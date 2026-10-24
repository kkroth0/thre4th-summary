const validDate = value => Number.isFinite(Date.parse(value));
const publicationKey=value=>{
    try{const url=new URL(value);for(const key of [...url.searchParams.keys()])if(/^utm_|^(?:fbclid|gclid)$/i.test(key))url.searchParams.delete(key);
        if(!url.hash.startsWith('#claim-'))url.hash='';return url.href;
    }catch{return value;}
};
export function actorPublications(archive, stories) {
    const rows = new Map();
    for (const row of archive || []) if (row.link) rows.set(publicationKey(row.link), row);
    for (const story of stories || []) for (const source of story.sources || []) if (source.link) rows.set(publicationKey(source.link), { ...rows.get(publicationKey(source.link)), ...Object.fromEntries(Object.entries(source).filter(([,value])=>value!==undefined)), storyId: story.id });
    return [...rows.values()];
}
export function buildActorActivity(rows, { days = 180, now = Date.now() } = {}) {
    const actors = new Map(); const cutoff = days ? now - days * 86400_000 : -Infinity;
    for (const row of rows) {
        if (!validDate(row.pubDate) || Date.parse(row.pubDate) < cutoff || Date.parse(row.pubDate) > now) continue;
        for (const id of new Set((row.actors || []).map(actor => actor.id).filter(Boolean))) {
            const entry = actors.get(id) || { ips: new Set(), domains: new Set(), hashes: new Set(), posts: new Set(), latest: null };
            for (const type of ['ips', 'domains', 'hashes']) for (const value of row.iocs?.[type] || []) if (type !== 'hashes' || /^[a-f0-9]{64}$/i.test(value)) entry[type].add(value.toLowerCase());
            entry.posts.add(row.link); if (!entry.latest || Date.parse(row.pubDate) > Date.parse(entry.latest)) entry.latest = row.pubDate;
            actors.set(id, entry);
        }
    }
    return Object.fromEntries([...actors].map(([id, row]) => [id, { ips: row.ips.size, domains: row.domains.size, hashes: row.hashes.size, posts: row.posts.size, latest: row.latest }]));
}
export function buildActorEvidence(rows, id, { days = 180, now = Date.now() } = {}) {
    const cutoff = days ? now - days * 86400_000 : -Infinity;
    const publications = rows.filter(row => (row.actors || []).some(actor => actor.id === id) && validDate(row.pubDate) && Date.parse(row.pubDate) >= cutoff && Date.parse(row.pubDate) <= now)
        .sort((a, b) => Date.parse(b.pubDate) - Date.parse(a.pubDate));
    const indicators = new Map();
    for (const row of publications) for (const type of ['ips', 'domains', 'hashes']) for (const value of row.iocs?.[type] || []) {
        if (type === 'hashes' && !/^[a-f0-9]{64}$/i.test(value)) continue;
        const key = `${type}:${value.toLowerCase()}`;
        const entry = indicators.get(key) || { value, type, evidence: [] };
        if (!entry.evidence.some(source => source.link === row.link)) entry.evidence.push({ title: row.title, source: row.source, link: row.link, pubDate: row.pubDate,
            actors: (row.actors || []).map(actor => actor.name), malware: (row.malware || []).map(item => item.name) });
        indicators.set(key, entry);
    }
    const all = [...indicators.values()];
    return { actorId: id, days, counts: { ips: all.filter(row => row.type === 'ips').length, domains: all.filter(row => row.type === 'domains').length, hashes: all.filter(row => row.type === 'hashes').length, posts: publications.length },
        indicators: all, publications: publications.map(row => ({ title: row.title, source: row.source, link: row.link, pubDate: row.pubDate, storyId: row.storyId || null })), latest: publications[0]?.pubDate || null };
}
