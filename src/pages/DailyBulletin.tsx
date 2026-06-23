import React, { useState, useEffect, useCallback } from "react";
import { RefreshCw, Download, Save, ShieldAlert, FileText, Loader2, ExternalLink, CalendarDays } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Footer } from "@/components/Footer";
import { Header } from "@/components/Header";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { toast } from "sonner";
import {
  fetchDailySuggestions, saveDailySelection, fetchDailyBoletim,
  type DailySuggestion, type DailyBoletim, type DeckType,
} from "@/services/threatApi";

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-500 border-red-500/20",
  High: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  Medium: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  Low: "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

const DailyBulletin: React.FC = () => {
  const { language } = useLanguage();
  const { isCollapsed } = useSidebar();
  const pt = language === "pt";

  const [suggestions, setSuggestions] = useState<DailySuggestion[]>([]);
  const [selected, setSelected] = useState<Record<string, DeckType>>({});
  const [boletim, setBoletim] = useState<DailyBoletim | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  const loadSuggestions = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchDailySuggestions(36, 12);
      setSuggestions(data.suggestions || []);
    } catch (e) {
      toast.error(pt ? "Falha ao carregar sugestões" : "Failed to load suggestions");
    } finally {
      setLoading(false);
    }
  }, [pt]);

  const loadBoletim = useCallback(async () => {
    try {
      setBoletim(await fetchDailyBoletim());
    } catch {
      /* sem boletim ainda — silencioso */
    }
  }, []);

  useEffect(() => { loadSuggestions(); loadBoletim(); }, [loadSuggestions, loadBoletim]);

  const toggle = (s: DailySuggestion) => {
    setSelected((prev) => {
      const next = { ...prev };
      if (next[s.url]) delete next[s.url];
      else next[s.url] = s.suggestedType;
      return next;
    });
  };

  const setType = (url: string, type: DeckType) =>
    setSelected((prev) => (prev[url] ? { ...prev, [url]: type } : prev));

  const selectedCount = Object.keys(selected).length;

  const save = async () => {
    const items = suggestions
      .filter((s) => selected[s.url])
      .map((s) => ({ url: s.url, type: selected[s.url], title: s.title }));
    if (!items.length) { toast.error(pt ? "Selecione ao menos um item" : "Select at least one item"); return; }
    setSaving(true);
    try {
      const res = await saveDailySelection(items);
      toast.success(pt ? `Seleção salva: ${res.count} item(ns)` : `Selection saved: ${res.count} item(s)`);
      loadBoletim();
    } catch (e) {
      toast.error((e as Error).message || (pt ? "Falha ao salvar" : "Failed to save"));
    } finally {
      setSaving(false);
    }
  };

  const downloadJson = (type: string, json: unknown) => {
    const blob = new Blob([JSON.stringify(json, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `boletim-${type}-${boletim?.date || "hoje"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const boletinsList = boletim ? Object.entries(boletim.boletins || {}) : [];

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-5xl">
        <div className="mb-8">
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <CalendarDays className="h-7 w-7 text-primary" />
            {pt ? "Boletim Diário" : "Daily Bulletin"}
          </h1>
          <p className="text-muted-foreground mt-2">
            {pt
              ? "Sugestões CTI do dia. Selecione as que entram no boletim, escolha o tipo de deck e salve a curadoria — o emissor gera o JSON e o render agent local produz o .pptx oficial."
              : "Today's CTI suggestions. Pick the ones for the bulletin, choose the deck type and save the selection — the emitter builds the JSON and the local render agent produces the official .pptx."}
          </p>
        </div>

        {/* Controles */}
        <div className="flex items-center justify-between mb-4">
          <Button variant="outline" size="sm" onClick={loadSuggestions} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
            {pt ? "Atualizar sugestões" : "Refresh suggestions"}
          </Button>
          <Button size="sm" onClick={save} disabled={saving || !selectedCount}>
            {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
            {pt ? `Salvar seleção (${selectedCount})` : `Save selection (${selectedCount})`}
          </Button>
        </div>

        {/* Sugestões */}
        <div className="space-y-3">
          {suggestions.map((s) => {
            const isSel = !!selected[s.url];
            return (
              <Card key={s.url} className={isSel ? "border-primary/50" : ""}>
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <Checkbox checked={isSel} onCheckedChange={() => toggle(s)} className="mt-1" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant="outline" className={SEVERITY_STYLES[s.severity] || SEVERITY_STYLES.Low}>
                          {s.severity}
                        </Badge>
                        <span className="text-xs text-muted-foreground">{s.source}</span>
                        <span className="text-xs text-muted-foreground">· score {s.score}</span>
                        {s.kev && (
                          <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20">
                            <ShieldAlert className="h-3 w-3 mr-1" /> CISA KEV
                          </Badge>
                        )}
                        {s.cves?.slice(0, 3).map((c) => (
                          <Badge key={c} variant="secondary" className="text-[10px]">{c}</Badge>
                        ))}
                      </div>
                      <a href={s.url} target="_blank" rel="noopener noreferrer"
                        className="font-medium hover:underline inline-flex items-center gap-1 mt-1">
                        {s.title} <ExternalLink className="h-3 w-3 shrink-0" />
                      </a>
                      {!!s.reasons?.length && (
                        <p className="text-xs text-muted-foreground mt-1 line-clamp-1">{s.reasons.join(" · ")}</p>
                      )}
                    </div>
                    <Select value={selected[s.url] || s.suggestedType} onValueChange={(v) => setType(s.url, v as DeckType)} disabled={!isSel}>
                      <SelectTrigger className="w-[130px] shrink-0">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="vuln">{pt ? "Vulnerabilidade" : "Vulnerability"}</SelectItem>
                        <SelectItem value="campaign">{pt ? "Campanha" : "Campaign"}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </CardContent>
              </Card>
            );
          })}
          {!loading && !suggestions.length && (
            <p className="text-center text-muted-foreground py-8">
              {pt ? "Nenhuma sugestão no momento." : "No suggestions right now."}
            </p>
          )}
        </div>

        {/* Boletim publicado */}
        <Card className="mt-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-primary" />
              {pt ? "Boletim publicado" : "Published bulletin"}
            </CardTitle>
            <CardDescription>
              {boletim?.updatedAt
                ? `${boletim.date} · ${pt ? "atualizado" : "updated"} ${new Date(boletim.updatedAt).toLocaleString()}`
                : (pt ? "Ainda não gerado para hoje." : "Not generated for today yet.")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {boletinsList.length ? (
              <div className="space-y-2">
                {boletinsList.map(([type, payload]) => (
                  <div key={type} className="flex items-center justify-between rounded-md border p-3">
                    <div>
                      <span className="font-medium capitalize">{type}</span>
                      <span className="text-xs text-muted-foreground ml-2">
                        {pt ? "publicado" : "published"} {new Date(payload.publishedAt).toLocaleTimeString()}
                      </span>
                    </div>
                    <Button variant="outline" size="sm" onClick={() => downloadJson(type, payload.json)}>
                      <Download className="h-4 w-4 mr-2" /> JSON
                    </Button>
                  </div>
                ))}
                <p className="text-xs text-muted-foreground pt-2">
                  {pt
                    ? "Para gerar o .pptx oficial (templates confidenciais, local): "
                    : "To produce the official .pptx (confidential templates, local): "}
                  <code className="px-1 py-0.5 rounded bg-muted">python tools/render_agent.py</code>
                </p>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                {pt
                  ? "Salve uma seleção e rode o emissor na VPS para publicar o boletim do dia."
                  : "Save a selection and run the emitter on the VPS to publish today's bulletin."}
              </p>
            )}
          </CardContent>
        </Card>
      </main>
      <Footer />
    </div>
  );
};

export default DailyBulletin;
