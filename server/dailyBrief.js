import crypto from 'crypto';

const WINDOW_HOURS = 36;
const DAY_MS = 24 * 60 * 60 * 1000;
const WINDOW_MS = WINDOW_HOURS * 60 * 60 * 1000;

const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;

const itemId = (item) => {
    const base = item.link || `${item.source || 'source'}:${item.title || 'untitled'}`;
    return crypto.createHash('sha256').update(String(base)).digest('hex').slice(0, 24);
};

export function buildExecutiveSummary({ kev, critical, victims, latamVictims, cves, highSignal }) {
    const bullets = [];

    if (kev.length) {
        bullets.push(`${plural(kev.length, 'KEV', 'KEVs')} nas ultimas 36h: priorize CVEs com exploracao conhecida.`);
    }

    if (critical.length) {
        bullets.push(`${plural(critical.length, 'advisory critico', 'advisories criticos')} no periodo, com foco em patching e exposicao externa.`);
    }

    if (victims.length) {
        const topGroup = victims.reduce((acc, victim) => {
            const group = victim.group || 'Unknown';
            acc.set(group, (acc.get(group) || 0) + 1);
            return acc;
        }, new Map());
        const [group] = [...topGroup.entries()].sort((a, b) => b[1] - a[1])[0] || [];
        bullets.push(`${plural(victims.length, 'vitima de ransomware', 'vitimas de ransomware')} reportada${victims.length === 1 ? '' : 's'}${group ? `; grupo mais recorrente: ${group}.` : '.'}`);
    }

    if (latamVictims.length) {
        bullets.push(`${plural(latamVictims.length, 'caso LATAM', 'casos LATAM')} no recorte de ransomware.`);
    }

    if (cves.length && !kev.length) {
        bullets.push(`${plural(cves.length, 'CVE unica', 'CVEs unicas')} apareceu${cves.length === 1 ? '' : 'ram'} no feed recente.`);
    }

    if (!bullets.length || !highSignal.length) {
        bullets.push('Nenhum sinal de alta prioridade dominou a janela de 36h.');
    }

    return bullets.slice(0, 5);
}

const advisoryItem = (item) => ({
    id: itemId(item),
    kind: 'advisory',
    title: item.title,
    titlePt: item.titlePt,
    link: item.link,
    source: item.source,
    pubDate: item.pubDate,
    score: item.score || 0,
    severity: item.severity || 'Low',
    cves: item.cves || [],
    kev: !!item.kev,
    reasons: item.reasons || [],
});

const ransomwareItem = (victim) => ({
    id: itemId({ link: `${victim.name}:${victim.group}:${victim.discovered}`, source: victim.source, title: victim.name }),
    kind: 'ransomware',
    title: victim.name,
    source: victim.source || 'ransomware.live',
    pubDate: victim.discovered || victim.published || null,
    cves: [],
    reasons: [],
    group: victim.group,
    countryName: victim.countryName,
    sector: victim.sector,
});

export function buildFeedGroups({ recent, victims }) {
    const used = new Set();
    const pick = (predicate) => recent.filter((item) => {
        const id = itemId(item);
        if (used.has(id) || !predicate(item)) return false;
        used.add(id);
        return true;
    }).map(advisoryItem);

    return [
        {
            key: 'kev',
            title: 'Exploracao ativa / KEV',
            description: 'Itens com CVEs conhecidas como exploradas ou sinal forte de exploracao.',
            items: pick((item) => item.kev || (item.reasons || []).some((reason) => /exploited|explor/i.test(reason))),
        },
        {
            key: 'critical',
            title: 'Criticas',
            description: 'Advisories criticos que ainda nao entraram no grupo KEV.',
            items: pick((item) => String(item.severity || '').toLowerCase() === 'critical'),
        },
        {
            key: 'ransomware',
            title: 'Ransomware',
            description: 'Vitimas e noticias relacionadas a ransomware no recorte recente.',
            items: [
                ...victims.map(ransomwareItem),
                ...pick((item) => /ransomware|extortion|leak site/i.test(`${item.title} ${item.description || ''} ${(item.reasons || []).join(' ')}`)),
            ],
        },
        {
            key: 'other',
            title: 'Outras noticias relevantes',
            description: 'Demais itens do feed das ultimas 36h.',
            items: pick(() => true),
        },
    ];
}

export function buildDailyBrief({ feed, victims, now = Date.now(), countBy, latamCountries }) {
    const recent = (feed || []).filter((item) => {
        const t = new Date(item.pubDate || item.date || 0).getTime();
        return Number.isFinite(t) && now - t <= WINDOW_MS;
    });
    const recentVictims = (victims || [])
        .filter((victim) => !victim.discovered || now - new Date(victim.discovered).getTime() <= DAY_MS)
        .slice(0, 12);
    const highSignal = recent.filter((item) => (item.score || 0) >= 65 || item.kev);
    const kev = recent.filter((item) => item.kev);
    const cves = [...new Set(recent.flatMap((item) => item.cves || []))];
    const critical = recent.filter((item) => String(item.severity || '').toLowerCase() === 'critical');
    const latamVictims = recentVictims.filter((victim) => latamCountries.has(victim.country));
    const verdict = kev.length || highSignal.length >= 6 || recentVictims.length >= 8 ? 'hot'
        : highSignal.length || recentVictims.length ? 'watch'
            : 'calm';
    const top = [...recent]
        .sort((a, b) => (b.kev ? 25 : 0) + (b.score || 0) - ((a.kev ? 25 : 0) + (a.score || 0)))
        .slice(0, 10);

    return {
        generatedAt: new Date(now).toISOString(),
        windowHours: WINDOW_HOURS,
        title: verdict === 'hot'
            ? 'Dia quente: priorize exploracao ativa, ransomware e advisories criticos'
            : verdict === 'watch'
                ? 'Dia de atencao: sinais relevantes em advisories e ransomware'
                : 'Dia calmo: monitore CVEs novas e mantenha correcoes planejadas',
        verdict,
        executiveSummary: buildExecutiveSummary({ kev, critical, victims: recentVictims, latamVictims, cves, highSignal }),
        summary: {
            totalAdvisories: recent.length,
            critical: critical.length,
            kev: kev.length,
            cves: cves.length,
            ransomwareVictims: recentVictims.length,
            latamVictims: latamVictims.length,
        },
        highlights: top.map(advisoryItem),
        ransomware: {
            victims: recentVictims,
            groups: countBy(recentVictims, (victim) => victim.group).slice(0, 8),
            latam: latamVictims,
        },
        feedGroups: buildFeedGroups({ recent, victims: recentVictims }),
        sources: ['RSS advisories', 'CISA KEV', 'FIRST EPSS', 'ransomware.live'],
    };
}
