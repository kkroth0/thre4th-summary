import crypto from 'crypto';
import fs from 'fs';

export const DAILY_TIMEZONE = 'America/Recife';
const DAY_MS = 86_400_000;
const PRIORITY_ORDER = { critical: 0, high: 1, context: 2 };

const localDateFormatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: DAILY_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
});

const hashId = (value) => crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 24);

const validDateParts = (date) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
    const [year, month, day] = date.split('-').map(Number);
    const probe = new Date(Date.UTC(year, month - 1, day));
    if (probe.getUTCFullYear() !== year || probe.getUTCMonth() !== month - 1 || probe.getUTCDate() !== day) return null;
    return { year, month, day };
};

const previousDate = (date) => {
    const { year, month, day } = validDateParts(date) || {};
    if (!year) throw new TypeError('invalid date');
    return new Date(Date.UTC(year, month - 1, day) - DAY_MS).toISOString().slice(0, 10);
};

export function getCompletedDate(now = new Date()) {
    const value = now instanceof Date ? now : new Date(now);
    if (Number.isNaN(value.getTime())) throw new TypeError('invalid date');
    const parts = Object.fromEntries(localDateFormatter.formatToParts(value).map((part) => [part.type, part.value]));
    return previousDate(`${parts.year}-${parts.month}-${parts.day}`);
}

export function getDateWindow(date) {
    if (!validDateParts(date)) throw new TypeError('invalid date');
    const start = new Date(`${date}T03:00:00.000Z`);
    return {
        windowStart: start.toISOString(),
        windowEnd: new Date(start.getTime() + DAY_MS).toISOString(),
    };
}

const eventTime = (item) => item.pubDate || item.date || item.discovered || item.published || null;

const classifyAdvisory = (item) => {
    const reasons = item.reasons || [];
    const active = !!item.kev || reasons.some((reason) => /exploited|explor/i.test(reason));
    const critical = String(item.severity || '').toLowerCase() === 'critical';
    return {
        category: active ? 'active-exploitation' : (item.cves || []).length ? 'vulnerability' : 'news',
        priority: active || critical ? 'critical' : (item.score || 0) >= 65 || String(item.severity || '').toLowerCase() === 'high' ? 'high' : 'context',
    };
};

const advisoryEvent = (item) => {
    const timestamp = eventTime(item);
    const classification = classifyAdvisory(item);
    return {
        id: hashId(item.link || `${item.source || 'source'}:${item.title || 'untitled'}:${timestamp}`),
        kind: 'advisory',
        title: item.title || 'Advisory sem titulo',
        titlePt: item.titlePt || null,
        link: item.link || null,
        source: item.source || 'Fonte desconhecida',
        timestamp,
        score: Number(item.score) || 0,
        severity: item.severity || 'Low',
        cves: [...new Set(item.cves || [])],
        kev: !!item.kev,
        reasons: item.reasons || [],
        ...classification,
    };
};

const ransomwareEvent = (victim) => {
    const timestamp = eventTime(victim);
    return {
        id: hashId(`${victim.name}:${victim.group}:${timestamp}`),
        kind: 'ransomware',
        title: victim.name || 'Vitima nao identificada',
        titlePt: null,
        link: victim.link || null,
        source: victim.source || 'ransomware.live',
        timestamp,
        score: 0,
        severity: null,
        cves: [],
        kev: false,
        reasons: [],
        priority: 'context',
        category: 'ransomware',
        group: victim.group || null,
        countryName: victim.countryName || null,
        sector: victim.sector || null,
    };
};

export function buildEditionEvents({ feed = [], victims = [], date }) {
    const { windowStart, windowEnd } = getDateWindow(date);
    const start = new Date(windowStart).getTime();
    const end = new Date(windowEnd).getTime();
    const inWindow = (item) => {
        const time = new Date(eventTime(item) || 0).getTime();
        return Number.isFinite(time) && time >= start && time < end;
    };
    return [
        ...feed.filter(inWindow).map(advisoryEvent),
        ...victims.filter(inWindow).map(ransomwareEvent),
    ].sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] || new Date(b.timestamp) - new Date(a.timestamp));
}

export function buildDeterministicNarrative(events) {
    if (!events.length) {
        return {
            title: 'Nenhum sinal prioritario no dia',
            summary: ['Nenhum evento de alta prioridade foi registrado nas fontes monitoradas.'],
            attentionTopics: [],
        };
    }

    const active = events.filter((event) => event.category === 'active-exploitation');
    const critical = events.filter((event) => event.priority === 'critical' && event.category !== 'active-exploitation');
    const ransomware = events.filter((event) => event.category === 'ransomware');
    const summary = [];
    const attentionTopics = [];

    if (active.length) {
        summary.push(`${active.length} ${active.length === 1 ? 'evento exige' : 'eventos exigem'} prioridade por sinal de exploracao ativa ou CISA KEV.`);
        attentionTopics.push({
            title: 'Exploracao ativa',
            assessment: 'Os itens abaixo possuem evidencia de exploracao ou constam no catalogo CISA KEV.',
            recommendedAction: 'Validar exposicao e priorizar a correcao dos ativos afetados.',
            eventIds: active.map((event) => event.id),
        });
    }
    if (critical.length) {
        summary.push(`${critical.length} ${critical.length === 1 ? 'advisory critico foi identificado' : 'advisories criticos foram identificados'} no periodo.`);
        attentionTopics.push({
            title: 'Vulnerabilidades criticas',
            assessment: 'Advisories criticos requerem avaliacao de aplicabilidade e exposicao externa.',
            recommendedAction: 'Cruzar produtos afetados com o inventario e planejar patching.',
            eventIds: critical.map((event) => event.id),
        });
    }
    if (ransomware.length) {
        const groups = [...new Set(ransomware.map((event) => event.group).filter(Boolean))];
        summary.push(`${ransomware.length} ${ransomware.length === 1 ? 'vitima de ransomware foi reportada' : 'vitimas de ransomware foram reportadas'}${groups[0] ? `; ${groups[0]} aparece entre os grupos observados.` : '.'}`);
        attentionTopics.push({
            title: 'Ameacas e campanhas',
            assessment: 'Novas publicacoes de ransomware compoem o contexto de ameacas do dia.',
            eventIds: ransomware.map((event) => event.id),
        });
    }
    if (!summary.length) summary.push(`${events.length} ${events.length === 1 ? 'evento relevante foi registrado' : 'eventos relevantes foram registrados'} nas fontes monitoradas.`);

    return {
        title: active.length || critical.length ? 'Correcao e exposicao lideram as prioridades do dia' : 'Principais mudancas observadas no dia',
        summary,
        attentionTopics,
    };
}

const requireText = (value, name, maxLength) => {
    if (typeof value !== 'string' || !value.trim() || value.length > maxLength) {
        throw new TypeError(`invalid ${name}`);
    }
    return value.trim();
};

export function validateNarrative(value, events) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('invalid narrative');
    const title = requireText(value.title, 'title', 140);
    if (!Array.isArray(value.summary) || value.summary.length < 3 || value.summary.length > 5) {
        throw new TypeError('invalid summary');
    }
    if (!Array.isArray(value.attentionTopics) || value.attentionTopics.length < 2 || value.attentionTopics.length > 4) {
        throw new TypeError('invalid attention topics');
    }

    const knownIds = new Set(events.map((event) => event.id));
    const knownCves = new Set(events.flatMap((event) => event.cves || []).map((cve) => String(cve).toUpperCase()));
    const summary = value.summary.map((line, index) => requireText(line, `summary ${index + 1}`, 320));
    const attentionTopics = value.attentionTopics.map((topic, index) => {
        if (!topic || typeof topic !== 'object' || Array.isArray(topic)) throw new TypeError(`invalid topic ${index + 1}`);
        if (!Array.isArray(topic.eventIds) || !topic.eventIds.length || topic.eventIds.some((id) => !knownIds.has(id))) {
            throw new TypeError('unknown event in narrative');
        }
        const normalized = {
            title: requireText(topic.title, `topic ${index + 1} title`, 100),
            assessment: requireText(topic.assessment, `topic ${index + 1} assessment`, 420),
            eventIds: [...new Set(topic.eventIds)],
        };
        if (topic.recommendedAction != null && String(topic.recommendedAction).trim()) {
            normalized.recommendedAction = requireText(topic.recommendedAction, `topic ${index + 1} action`, 280);
        }
        return normalized;
    });

    const identifiers = JSON.stringify({ title, summary, attentionTopics }).match(/CVE-\d{4}-\d{4,}/gi) || [];
    if (identifiers.some((identifier) => !knownCves.has(identifier.toUpperCase()))) {
        throw new TypeError('unsupported identifier in narrative');
    }

    return { title, summary, attentionTopics };
}

export function createEditionStore({ filePath, writeJsonAtomic }) {
    let editions = [];
    try {
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        editions = Array.isArray(parsed) ? parsed.filter((edition) => edition && validDateParts(edition.date)) : [];
    } catch { /* empty store */ }

    return {
        listDates: () => editions.map((edition) => edition.date).sort().reverse(),
        get: (date) => editions.find((edition) => edition.date === date) || null,
        save(edition) {
            const existing = editions.find((item) => item.date === edition.date);
            if (existing) return existing;
            editions.push(edition);
            editions.sort((a, b) => a.date.localeCompare(b.date));
            writeJsonAtomic(filePath, editions);
            return edition;
        },
    };
}

export function createEditionGenerator({ store, requestNarrative, getSourceData, now = () => new Date() }) {
    const inFlight = new Map();

    const generateNew = async (date) => {
        const existing = store.get(date);
        if (existing) return existing;

        const { feed = [], victims = [] } = await getSourceData();
        const events = buildEditionEvents({ feed, victims, date });
        let narrative;
        let narrativeSource = 'deterministic';
        if (events.length) {
            try {
                narrative = validateNarrative(await requestNarrative(events, date), events);
                narrativeSource = 'openrouter';
            } catch { /* deterministic fallback */ }
        }
        if (!narrative) narrative = buildDeterministicNarrative(events);

        const { windowStart, windowEnd } = getDateWindow(date);
        return store.save({
            date,
            timezone: DAILY_TIMEZONE,
            windowStart,
            windowEnd,
            generatedAt: now().toISOString(),
            narrativeSource,
            narrative,
            events,
            sources: [...new Set(events.map((event) => event.source))],
        });
    };

    return {
        generate(date) {
            if (!validDateParts(date)) return Promise.reject(new TypeError('invalid date'));
            const existing = store.get(date);
            if (existing) return Promise.resolve(existing);
            if (!inFlight.has(date)) {
                inFlight.set(date, generateNew(date).finally(() => inFlight.delete(date)));
            }
            return inFlight.get(date);
        },
    };
}
