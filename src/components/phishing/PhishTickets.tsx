// A fila de trabalho da vigilância de marca. O achado responde "o que
// apareceu"; o ticket responde "o que a gente fez e como terminou".
import { useCallback, useEffect, useState } from "react";
import { Check, ChevronDown, Clock, Copy, ExternalLink, Loader2, RotateCcw, Send, Skull } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useLanguage } from "@/contexts/LanguageContext";
import { useOrgProfile } from "@/hooks/useOrgProfile";
import { toast } from "sonner";
import { defang } from "@/utils/defang";
import {
  fetchPhishTicket, fetchPhishTickets, setPhishTicketStatus,
  type PhishTicket, type TicketDigest, type TicketStatus,
} from "@/services/threatApi";

const STATUS_LABEL: Record<TicketStatus, { pt: string; en: string; tone: string }> = {
  open: { pt: "Aberto", en: "Open", tone: "text-red-500 border-red-500/30 bg-red-500/10" },
  analysis: { pt: "Em análise", en: "In analysis", tone: "text-amber-500 border-amber-500/30 bg-amber-500/10" },
  takedown: { pt: "Takedown pedido", en: "Takedown sent", tone: "text-blue-500 border-blue-500/30 bg-blue-500/10" },
  down: { pt: "Derrubado", en: "Taken down", tone: "text-green-500 border-green-500/30 bg-green-500/10" },
  closed: { pt: "Encerrado", en: "Closed", tone: "text-muted-foreground border-border/60" },
};

const daysSince = (iso: string): number => Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);

export function PhishTickets() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const { profiles, activeId, setActiveId } = useOrgProfile();

  const [filter, setFilter] = useState<"open" | "" | TicketStatus>("open");
  const [tickets, setTickets] = useState<PhishTicket[]>([]);
  const [digest, setDigest] = useState<TicketDigest | null>(null);
  const [loading, setLoading] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [detail, setDetail] = useState<{ ticket: PhishTicket; takedown: { pt: string; en: string } } | null>(null);

  const load = useCallback(async (profileId: string, status: string) => {
    setLoading(true);
    try {
      const data = await fetchPhishTickets(profileId, status);
      setTickets(data.tickets);
      setDigest(data.digest);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "erro");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!activeId) { setTickets([]); setDigest(null); return; }
    load(activeId, filter);
  }, [activeId, filter, load]);

  const openDetail = async (id: string) => {
    if (openId === id) { setOpenId(null); setDetail(null); return; }
    setOpenId(id);
    setDetail(null);
    try {
      setDetail(await fetchPhishTicket(id));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "erro");
    }
  };

  const move = async (id: string, status: TicketStatus) => {
    try {
      const { ticket } = await setPhishTicketStatus(id, status);
      setTickets((current) => (filter === "open" && !["open", "analysis", "takedown"].includes(status)
        ? current.filter((item) => item.id !== id)
        : current.map((item) => (item.id === id ? ticket : item))));
      if (detail?.ticket.id === id) setDetail({ ...detail, ticket });
      if (activeId) load(activeId, filter);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "erro");
    }
  };

  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    toast.success(pt ? "Pedido copiado" : "Request copied");
  };

  const filters: { key: "open" | "" | TicketStatus; label: string }[] = [
    { key: "open", label: pt ? "Em aberto" : "Open" },
    { key: "takedown", label: pt ? "Takedown pedido" : "Takedown sent" },
    { key: "down", label: pt ? "Derrubados" : "Taken down" },
    { key: "closed", label: pt ? "Encerrados" : "Closed" },
    { key: "", label: pt ? "Todos" : "All" },
  ];

  if (!profiles.length) {
    return (
      <Card className="border-dashed">
        <CardContent className="p-10 text-center text-sm text-muted-foreground">
          {pt ? "A fila vem da vigilância de marca, que usa o perfil da organização." : "The queue comes from the brand watch, which uses the organization profile."}
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 rounded-lg border bg-card p-3 xl:flex-row xl:items-center">
        <select
          value={activeId}
          onChange={(event) => setActiveId(event.target.value)}
          className="rounded-md border bg-background px-2 py-1.5 text-xs"
          aria-label={pt ? "Perfil da organização" : "Organization profile"}
        >
          <option value="">{pt ? "Escolha um perfil" : "Pick a profile"}</option>
          {profiles.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
        </select>

        {digest && (
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground xl:ml-auto">
            <span><strong className="text-foreground tabular-nums">{digest.openCount}</strong> {pt ? "em aberto" : "open"}</span>
            <span>{pt ? "hoje: " : "today: "}<strong className="text-foreground tabular-nums">{digest.opened.length}</strong></span>
            {digest.reopened.length > 0 && <span className="text-amber-500">{pt ? "reincidentes: " : "recurring: "}{digest.reopened.length}</span>}
            {digest.dropped.length > 0 && <span className="text-green-600">{pt ? "caíram: " : "dropped: "}{digest.dropped.length}</span>}
            {digest.aging.length > 0 && <span className="text-red-500">{pt ? "parados: " : "stalled: "}{digest.aging.length}</span>}
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        {filters.map((item) => (
          <button
            key={item.key || "all"}
            type="button"
            onClick={() => setFilter(item.key)}
            aria-pressed={filter === item.key}
            className={`rounded-full border px-3 py-1 text-xs transition ${filter === item.key ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
          >
            {item.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="space-y-3">{[1, 2].map((n) => <div key={n} className="h-20 animate-pulse rounded-lg border bg-card" />)}</div>
      ) : !tickets.length ? (
        <EmptyState
          title={pt ? "Nada na fila" : "Nothing in the queue"}
          description={pt
            ? "Abra um ticket a partir de um domínio suspeito para acompanhar o takedown aqui."
            : "Open a ticket from a suspicious domain to track its takedown here."}
        />
      ) : (
        <div className="space-y-2">
          {tickets.map((ticket) => {
            const label = STATUS_LABEL[ticket.status];
            const stalled = ["open", "analysis", "takedown"].includes(ticket.status) && daysSince(ticket.updatedAt) >= 3;
            return (
              <Card key={ticket.id} className={openId === ticket.id ? "border-primary/40" : ""}>
                <CardContent className="p-3">
                  <button type="button" onClick={() => openDetail(ticket.id)} className="flex w-full items-center gap-3 text-left">
                    <Badge variant="outline" className={`shrink-0 text-[10px] ${label.tone}`}>{pt ? label.pt : label.en}</Badge>
                    <span className="min-w-0 flex-1 break-all font-mono text-sm font-semibold">{defang(ticket.apexDomain)}</span>
                    {ticket.reopenedAt && <Badge variant="outline" className="shrink-0 border-amber-500/30 text-[10px] text-amber-500">{pt ? "reincidente" : "recurring"}</Badge>}
                    {ticket.dns?.deadAt && <Badge variant="outline" className="shrink-0 border-green-500/30 text-[10px] text-green-600">{pt ? "não resolve" : "no DNS"}</Badge>}
                    <span className={`shrink-0 text-[11px] tabular-nums ${stalled ? "text-red-500" : "text-muted-foreground"}`}>
                      <Clock className="mr-1 inline h-3 w-3" />{daysSince(ticket.openedAt)}d
                    </span>
                    <ChevronDown className={`h-4 w-4 shrink-0 text-muted-foreground transition ${openId === ticket.id ? "rotate-180" : ""}`} />
                  </button>

                  {openId === ticket.id && (
                    !detail ? <div className="p-4 text-center"><Loader2 className="mx-auto h-4 w-4 animate-spin text-muted-foreground" /></div> : (
                      <div className="mt-3 space-y-3 border-t pt-3">
                        <div className="flex flex-col gap-3 sm:flex-row">
                          {detail.ticket.screenshot && (
                            <img src={detail.ticket.screenshot} alt="" loading="lazy" referrerPolicy="no-referrer" className="h-28 w-44 shrink-0 rounded border object-cover object-top" />
                          )}
                          <dl className="grid flex-1 grid-cols-2 gap-x-4 gap-y-1 text-[11px]">
                            <dt className="text-muted-foreground">IP</dt><dd className="font-mono">{detail.ticket.evidence?.ip || "—"}</dd>
                            <dt className="text-muted-foreground">{pt ? "Hospedagem" : "Hosting"}</dt><dd>{detail.ticket.evidence?.hosting?.holder || detail.ticket.evidence?.hosting?.network || "—"}</dd>
                            <dt className="text-muted-foreground">{pt ? "Registrador" : "Registrar"}</dt><dd>{detail.ticket.evidence?.registration?.registrar || "—"}</dd>
                            <dt className="text-muted-foreground">{pt ? "Registrado em" : "Registered"}</dt><dd>{(detail.ticket.evidence?.registration?.registeredAt || "—").slice(0, 10)}</dd>
                          </dl>
                        </div>

                        {detail.ticket.targets.length > 0 && (
                          <div className="space-y-1">
                            <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{pt ? "Para onde mandar" : "Where to send"}</p>
                            <div className="flex flex-wrap gap-1.5">
                              {detail.ticket.targets.map((target, index) => (
                                <Badge key={`${target.email || target.url}-${index}`} variant="secondary" className="gap-1 text-[10px]">
                                  {target.kind === "hosting" ? "🖥" : target.kind === "registrar" ? "🏷" : "📣"}
                                  {target.email || target.name}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}

                        <details className="rounded-md border bg-muted/30">
                          <summary className="cursor-pointer p-2 text-xs font-semibold">{pt ? "Pedido de takedown" : "Takedown request"}</summary>
                          <div className="space-y-2 p-2">
                            <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded bg-background p-2 text-[11px] leading-relaxed">{pt ? detail.takedown.pt : detail.takedown.en}</pre>
                            <div className="flex gap-1.5">
                              <Button size="sm" variant="outline" className="h-7 gap-1.5 text-xs" onClick={() => copy(pt ? detail.takedown.pt : detail.takedown.en)}>
                                <Copy className="h-3 w-3" /> {pt ? "Copiar" : "Copy"}
                              </Button>
                              <Button size="sm" variant="ghost" className="h-7 gap-1.5 text-xs" onClick={() => copy(pt ? detail.takedown.en : detail.takedown.pt)}>
                                {pt ? "Copiar em inglês" : "Copy in Portuguese"}
                              </Button>
                            </div>
                          </div>
                        </details>

                        <div className="flex flex-wrap gap-1.5">
                          <Button asChild size="sm" variant="outline" className="h-7 gap-1.5 text-xs">
                            <a href={detail.ticket.scanUrl} target="_blank" rel="noopener noreferrer"><ExternalLink className="h-3 w-3" /> urlscan</a>
                          </Button>
                          <Button size="sm" variant="outline" className="h-7 gap-1.5 text-xs" onClick={() => move(ticket.id, "analysis")}>
                            {pt ? "Em análise" : "In analysis"}
                          </Button>
                          <Button size="sm" variant="outline" className="h-7 gap-1.5 text-xs" onClick={() => move(ticket.id, "takedown")}>
                            <Send className="h-3 w-3" /> {pt ? "Takedown pedido" : "Takedown sent"}
                          </Button>
                          <Button size="sm" variant="outline" className="h-7 gap-1.5 border-green-500/30 text-xs text-green-600" onClick={() => move(ticket.id, "down")}>
                            <Skull className="h-3 w-3" /> {pt ? "Derrubado" : "Taken down"}
                          </Button>
                          <Button size="sm" variant="ghost" className="h-7 gap-1.5 text-xs text-muted-foreground" onClick={() => move(ticket.id, "closed")}>
                            <Check className="h-3 w-3" /> {pt ? "Encerrar" : "Close"}
                          </Button>
                          {!["open"].includes(ticket.status) && (
                            <Button size="sm" variant="ghost" className="h-7 gap-1.5 text-xs text-muted-foreground" onClick={() => move(ticket.id, "open")}>
                              <RotateCcw className="h-3 w-3" /> {pt ? "Reabrir" : "Reopen"}
                            </Button>
                          )}
                        </div>

                        <ol className="space-y-1 border-t pt-2 text-[11px] text-muted-foreground">
                          {detail.ticket.events.map((item, index) => (
                            <li key={`${item.at}-${index}`}>
                              <span className="tabular-nums">{item.at.slice(0, 16).replace("T", " ")}</span>
                              {" · "}{item.kind}{item.by ? ` · ${item.by}` : ""}{item.note ? ` — ${item.note}` : ""}
                            </li>
                          ))}
                        </ol>
                      </div>
                    )
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
