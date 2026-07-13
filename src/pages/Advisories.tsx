import { useCallback, useEffect, useMemo, useState } from "react";
import { CalendarDays, ExternalLink, Loader2, Megaphone, RefreshCw, Rss, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchDailyBrief, type DailyBriefResponse, type DailySummaryEvent } from "@/services/threatApi";

const LOCALE: Record<string, string> = { pt: "pt-BR", en: "en-US", es: "es-ES", fr: "fr-FR" };
const PRIORITIES = ["all", "critical", "high", "context"] as const;
const CATEGORIES = ["all", "active-exploitation", "vulnerability", "ransomware", "news"] as const;

const formatDate = (date: string, lang: string) =>
    new Date(`${date}T12:00:00Z`).toLocaleDateString(LOCALE[lang] || "pt-BR", { day: "2-digit", month: "long", year: "numeric" });

const formatPeriod = (start: string, end: string, lang: string) => {
    const options: Intl.DateTimeFormatOptions = { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "America/Recife" };
    const formatter = new Intl.DateTimeFormat(LOCALE[lang] || "pt-BR", options);
    return `${formatter.format(new Date(start))} — ${formatter.format(new Date(new Date(end).getTime() - 1))}`;
};

const categoryLabel: Record<string, string> = {
    "active-exploitation": "exploração ativa",
    vulnerability: "vulnerabilidade",
    ransomware: "ransomware",
    news: "notícia",
};

const eventTitle = (event: DailySummaryEvent, language: string) => language === "pt" ? event.titlePt || event.title : event.title;

const EventRow = ({ event, language }: { event: DailySummaryEvent; language: string }) => (
    <article className="grid gap-3 border-b border-border/70 py-5 last:border-0 md:grid-cols-[10rem_1fr]">
        <div className="space-y-1 text-xs text-muted-foreground">
            <div className="font-semibold text-foreground">{event.source}</div>
            <time>{new Date(event.timestamp).toLocaleString(LOCALE[language] || "pt-BR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "America/Recife" })}</time>
        </div>
        <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-2">
                <Badge variant={event.priority === "critical" ? "destructive" : "secondary"}>{event.priority}</Badge>
                <Badge variant="outline">{categoryLabel[event.category]}</Badge>
                {event.kev ? <Badge variant="destructive">CISA KEV</Badge> : null}
                {event.severity ? <span className="text-xs font-medium text-muted-foreground">{event.severity}</span> : null}
            </div>
            {event.link ? (
                <a href={event.link} target="_blank" rel="noreferrer" className="inline-flex items-start gap-2 font-semibold leading-snug text-foreground hover:text-primary">
                    <span>{eventTitle(event, language)}</span><ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                </a>
            ) : <h3 className="font-semibold leading-snug">{eventTitle(event, language)}</h3>}
            {event.kind === "ransomware" ? (
                <p className="mt-2 text-xs text-muted-foreground">{[event.group, event.countryName, event.sector].filter(Boolean).join(" · ")}</p>
            ) : event.cves.length ? (
                <p className="mt-2 font-mono text-xs text-muted-foreground">{event.cves.join(" · ")}</p>
            ) : null}
        </div>
    </article>
);

const Advisories = () => {
    const { language } = useLanguage();
    const [data, setData] = useState<DailyBriefResponse | null>(null);
    const [selectedDate, setSelectedDate] = useState<string>();
    const [priority, setPriority] = useState<(typeof PRIORITIES)[number]>("all");
    const [category, setCategory] = useState<(typeof CATEGORIES)[number]>("all");
    const [source, setSource] = useState("all");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    const load = useCallback(async (date?: string) => {
        setLoading(true);
        setError("");
        try {
            const result = await fetchDailyBrief(date);
            setData(result);
            setSelectedDate(result.edition.date);
        } catch (cause) {
            setError(cause instanceof Error ? cause.message : "Falha ao carregar a edição.");
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { void load(); }, [load]);

    const edition = data?.edition;
    const eventMap = useMemo(() => new Map((edition?.events || []).map((event) => [event.id, event])), [edition?.events]);
    const sources = useMemo(() => [...new Set((edition?.events || []).map((event) => event.source))].sort(), [edition?.events]);
    const filteredEvents = useMemo(() => (edition?.events || []).filter((event) =>
        (priority === "all" || event.priority === priority) &&
        (category === "all" || event.category === category) &&
        (source === "all" || event.source === source)
    ), [edition?.events, priority, category, source]);

    return (
        <PageLayout width="max-w-6xl" showBackButton={false}>
            <header className="mb-10 border-b border-border pb-7">
                <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
                    <div>
                        <h1 className="flex items-center gap-3 text-3xl font-black tracking-tight"><Megaphone className="h-7 w-7 text-primary" />Summ4ry diário</h1>
                        {edition ? <p className="mt-2 text-sm text-muted-foreground">{formatDate(edition.date, language)} · {formatPeriod(edition.windowStart, edition.windowEnd, language)}</p> : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                        <label className="sr-only" htmlFor="edition-date">Edição</label>
                        <select id="edition-date" value={selectedDate || ""} disabled={!data?.availableDates.length || loading} onChange={(event) => void load(event.target.value)} className="h-9 rounded-md border border-input bg-background px-3 text-sm font-medium">
                            {(data?.availableDates || []).map((date) => <option key={date} value={date}>{formatDate(date, language)}</option>)}
                        </select>
                        <Button asChild variant="outline" size="icon" title="RSS"><a href="/api/advisories/feed.xml" target="_blank" rel="noreferrer"><Rss className="h-4 w-4" /></a></Button>
                    </div>
                </div>
            </header>

            {loading && !edition ? <div className="flex justify-center gap-2 py-20 text-muted-foreground"><Loader2 className="h-5 w-5 animate-spin" />Carregando edição…</div> : null}
            {error ? (
                <div className="mb-8 flex flex-col items-start gap-4 border-y border-destructive/30 py-6 text-sm">
                    <p className="text-destructive">{error}</p>
                    <Button variant="outline" onClick={() => void load(selectedDate)}><RefreshCw className="mr-2 h-4 w-4" />Tentar novamente</Button>
                </div>
            ) : null}

            {edition ? <div className="space-y-14">
                <section aria-labelledby="summary-heading" className="grid gap-7 border-b border-border pb-12 lg:grid-cols-[0.72fr_1.28fr]">
                    <div><h2 id="summary-heading" className="text-sm font-bold uppercase tracking-[0.18em] text-muted-foreground">Em poucas linhas</h2><h3 className="mt-4 text-3xl font-black leading-tight tracking-tight">{edition.narrative.title}</h3></div>
                    <ul className="space-y-4 pt-1">{edition.narrative.summary.map((line) => <li key={line} className="flex gap-3 leading-relaxed"><span className="mt-2.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" /><span>{line}</span></li>)}</ul>
                </section>

                <section aria-labelledby="attention-heading">
                    <div className="mb-6 flex items-center gap-2"><ShieldAlert className="h-5 w-5 text-primary" /><h2 id="attention-heading" className="text-2xl font-black tracking-tight">O que merece sua atenção</h2></div>
                    {edition.narrative.attentionTopics.length ? <div className="divide-y divide-border border-y border-border">{edition.narrative.attentionTopics.map((topic) => {
                        const supporting = topic.eventIds.map((id) => eventMap.get(id)).filter((event): event is DailySummaryEvent => Boolean(event));
                        return <article key={`${topic.title}-${topic.eventIds.join("-")}`} className="grid gap-5 py-7 lg:grid-cols-[0.8fr_1.2fr]">
                            <div><h3 className="text-xl font-bold">{topic.title}</h3><p className="mt-2 text-sm leading-relaxed text-muted-foreground">{topic.assessment}</p>{topic.recommendedAction ? <p className="mt-4 border-l-2 border-primary pl-3 text-sm font-medium">{topic.recommendedAction}</p> : null}</div>
                            <div className="space-y-3">{supporting.map((event) => <a key={event.id} href={event.link || undefined} target={event.link ? "_blank" : undefined} rel={event.link ? "noreferrer" : undefined} className="block border-l border-border pl-4 text-sm font-semibold leading-snug hover:border-primary hover:text-primary">{eventTitle(event, language)}</a>)}</div>
                        </article>;
                    })}</div> : <p className="border-y border-border py-8 text-sm text-muted-foreground">Nenhum tema prioritário foi identificado nesta edição.</p>}
                </section>

                <section aria-labelledby="events-heading">
                    <div className="mb-6 flex flex-col gap-5 border-b border-border pb-5 lg:flex-row lg:items-end lg:justify-between">
                        <div><h2 id="events-heading" className="text-2xl font-black tracking-tight">Todos os eventos</h2><p className="mt-1 text-sm text-muted-foreground">{edition.events.length} eventos preservados nesta edição.</p></div>
                        <div className="grid gap-2 sm:grid-cols-3">
                            <select aria-label="Filtrar por prioridade" value={priority} onChange={(event) => setPriority(event.target.value as typeof priority)} className="h-9 rounded-md border border-input bg-background px-3 text-sm">{PRIORITIES.map((value) => <option key={value} value={value}>{value === "all" ? "Todas as prioridades" : value}</option>)}</select>
                            <select aria-label="Filtrar por categoria" value={category} onChange={(event) => setCategory(event.target.value as typeof category)} className="h-9 rounded-md border border-input bg-background px-3 text-sm">{CATEGORIES.map((value) => <option key={value} value={value}>{value === "all" ? "Todas as categorias" : categoryLabel[value]}</option>)}</select>
                            <select aria-label="Filtrar por fonte" value={source} onChange={(event) => setSource(event.target.value)} className="h-9 rounded-md border border-input bg-background px-3 text-sm"><option value="all">Todas as fontes</option>{sources.map((value) => <option key={value} value={value}>{value}</option>)}</select>
                        </div>
                    </div>
                    {filteredEvents.length ? <div className="content-visibility-auto">{filteredEvents.map((event) => <EventRow key={event.id} event={event} language={language} />)}</div> : <div className="flex flex-col items-center gap-2 py-14 text-center text-muted-foreground"><CalendarDays className="h-7 w-7" /><p>{edition.events.length ? "Nenhum evento corresponde aos filtros." : "Nenhum evento relevante foi registrado nesta edição."}</p></div>}
                </section>
            </div> : null}
        </PageLayout>
    );
};

export default Advisories;
