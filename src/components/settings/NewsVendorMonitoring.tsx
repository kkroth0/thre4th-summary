import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Building2, Check, Loader2, Search } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useLanguage } from "@/contexts/LanguageContext";
import { useNewsMonitoring } from "@/hooks/useNewsMonitoring";
import type { NewsMonitoringPreferences } from "@/services/threatApi";
import { filterNewsVendors, NEWS_VENDOR_SECTORS, setNewsVendorSelection } from "@/utils/newsVendorSelection";

export function NewsVendorMonitoring() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const { data, isPending, error, refetch, save } = useNewsMonitoring();
  const [draft, setDraft] = useState<Pick<NewsMonitoringPreferences, "mode" | "vendorIds"> | null>(null);
  const [search, setSearch] = useState("");
  const [sector, setSector] = useState("all");
  const [selectedOnly, setSelectedOnly] = useState(false);
  const [saving, setSaving] = useState(false);
  const preferences = draft ?? data?.preferences ?? { mode: "all", vendorIds: [] };
  const selected = useMemo(() => new Set(preferences.vendorIds), [preferences.vendorIds]);
  const visible = useMemo(() => filterNewsVendors(data?.vendors ?? [], { search, sector, selectedOnly, selectedIds: preferences.vendorIds }),
    [data?.vendors, search, sector, selectedOnly, preferences.vendorIds]);
  const dirty = !!data && (preferences.mode !== data.preferences.mode
    || [...preferences.vendorIds].sort().join(",") !== [...data.preferences.vendorIds].sort().join(","));
  const changeSelection = (ids: string[], checked: boolean) => setDraft({ mode: "selected", vendorIds: setNewsVendorSelection(preferences.vendorIds, ids, checked) });
  const saveSelection = async () => {
    setSaving(true);
    try {
      await save(preferences);
      setDraft(null);
      toast.success(pt ? "Monitoramento de notícias salvo" : "News monitoring saved");
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : (pt ? "Não foi possível salvar" : "Unable to save"));
    } finally { setSaving(false); }
  };

  return (
    <Card className="rounded-sm shadow-none" id="news-vendors">
      <CardHeader className="p-4 pb-3">
        <CardTitle className="flex items-center gap-2 text-sm"><Building2 className="h-4 w-4 text-muted-foreground" />{pt ? "Fornecedores nas notícias" : "Vendors in the news"}</CardTitle>
        <CardDescription>{pt
          ? "Filtre o feed por fornecedores e projetos de software. Seleção vinculada à conta."
          : "Filter the feed by vendors and software projects. Selection is tied to your account."}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 px-4 pb-4">
        {isPending ? <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />{pt ? "Carregando fornecedores…" : "Loading vendors…"}</p>
          : error ? <div role="alert" className="space-y-2 text-sm"><p>{pt ? "Não foi possível carregar seu monitoramento." : "Unable to load your monitoring."}</p><Button size="sm" variant="outline" onClick={() => refetch()}>{pt ? "Tentar novamente" : "Retry"}</Button></div>
            : <>
              <fieldset disabled={saving} className="flex flex-wrap gap-x-5 gap-y-2 border-b border-border pb-3 text-sm">
                <legend className="sr-only">{pt ? "Quais notícias mostrar" : "Which news to display"}</legend>
                <label className="flex cursor-pointer items-center gap-2"><input type="radio" name="news-vendor-mode" value="all" checked={preferences.mode === "all"} onChange={() => setDraft({ ...preferences, mode: "all" })} className="accent-primary" />{pt ? "Todas as notícias" : "All news"}</label>
                <label className="flex cursor-pointer items-center gap-2"><input type="radio" name="news-vendor-mode" value="selected" checked={preferences.mode === "selected"} onChange={() => setDraft({ ...preferences, mode: "selected" })} className="accent-primary" />{pt ? "Somente fornecedores selecionados" : "Selected vendors only"}</label>
              </fieldset>
              {preferences.mode === "selected" && <>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <div className="relative flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" /><Input aria-label={pt ? "Buscar fornecedor ou produto" : "Search vendor or product"} placeholder={pt ? "Buscar fornecedor ou produto, ex.: FortiGate" : "Search vendor or product, e.g. FortiGate"} value={search} onChange={(event) => setSearch(event.target.value)} className="pl-9" /></div>
                  <Select value={sector} onValueChange={setSector}><SelectTrigger className="sm:w-60" aria-label={pt ? "Setor do fornecedor" : "Vendor sector"}><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">{pt ? "Todos os setores" : "All sectors"}</SelectItem>{Object.entries(NEWS_VENDOR_SECTORS).map(([id, label]) => <SelectItem key={id} value={id}>{pt ? label.pt : label.en}</SelectItem>)}</SelectContent></Select>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-muted-foreground">{selected.size} / {data?.vendors.length} {pt ? "selecionados" : "selected"}</span>
                  <Button type="button" size="sm" variant="ghost" aria-pressed={selectedOnly} onClick={() => setSelectedOnly(!selectedOnly)}>{selectedOnly ? (pt ? "Ver todos" : "Show all") : (pt ? "Ver selecionados" : "Show selected")}</Button>
                  <span className="ml-auto text-xs text-muted-foreground">{visible.length} {pt ? "resultados" : "results"}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" disabled={saving || !visible.length} onClick={() => changeSelection(visible.map((vendor) => vendor.id), true)}>{pt ? "Selecionar resultados" : "Select results"}</Button>
                  <Button size="sm" variant="outline" disabled={saving || !visible.length} onClick={() => changeSelection(visible.map((vendor) => vendor.id), false)}>{pt ? "Desmarcar resultados" : "Deselect results"}</Button>
                  <Button size="sm" variant="ghost" disabled={saving || !selected.size} onClick={() => setDraft({ mode: "selected", vendorIds: [] })}>{pt ? "Limpar seleção" : "Clear selection"}</Button>
                </div>
                <div className="max-h-80 overflow-auto rounded-sm border" aria-label={pt ? "Catálogo de fornecedores" : "Vendor catalog"}>
                  <div className="sticky top-0 z-10 grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-3 border-b bg-muted px-3 py-2 text-xs font-medium text-muted-foreground sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]"><span>{pt ? "Fornecedor / projeto" : "Vendor / project"}</span><span>{pt ? "Setor" : "Sector"}</span><span className="hidden sm:block">{pt ? "Produtos / aliases" : "Products / aliases"}</span></div>
                  {visible.map((vendor) => <label key={vendor.id} className="grid cursor-pointer grid-cols-[minmax(0,1fr)_minmax(0,1fr)] items-center gap-3 border-b border-border/60 px-3 py-2 last:border-b-0 hover:bg-muted/50 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
                    <span className="flex min-w-0 items-center gap-2.5">
                    <Checkbox checked={selected.has(vendor.id)} disabled={saving} onCheckedChange={(checked) => changeSelection([vendor.id], checked === true)} aria-label={vendor.name} className="mt-0.5" />
                    <span className="truncate text-sm font-medium">{vendor.name}</span></span>
                    <span className="text-xs text-muted-foreground">{pt ? NEWS_VENDOR_SECTORS[vendor.sector]?.pt : NEWS_VENDOR_SECTORS[vendor.sector]?.en}</span>
                    <span className="col-span-2 line-clamp-2 break-words text-xs text-muted-foreground sm:col-span-1" title={vendor.aliases.join(", ")}>{vendor.aliases.filter((alias) => alias.toLowerCase() !== vendor.name.toLowerCase()).join(", ") || vendor.aliases.join(", ")}</span>
                  </label>)}
                  {!visible.length && <p className="col-span-full p-4 text-center text-sm text-muted-foreground">{pt ? "Nenhum fornecedor encontrado. Ajuste a busca ou os filtros." : "No vendors found. Adjust your search or filters."}</p>}
                </div>
                <p className="text-xs text-muted-foreground">{selected.size === 0
                  ? (pt ? "Nenhum selecionado: ao salvar, seu feed ficará vazio até você escolher um fornecedor ou voltar a todas as notícias." : "None selected: saving will leave your feed empty until you choose a vendor or switch back to all news.")
                  : (pt ? "Um evento entra no feed quando alguma fonte menciona um fornecedor selecionado. As outras fontes desse evento continuam no mesmo card." : "An event appears when a source mentions a selected vendor. Other sources covering that event stay in the same card.")}</p>
              </>}
              <div className="flex flex-wrap items-center gap-2 border-t pt-4">
                <Button size="sm" disabled={saving || !dirty} onClick={saveSelection}>{saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Check className="mr-2 h-4 w-4" />}{pt ? "Salvar monitoramento" : "Save monitoring"}</Button>
                {dirty && <Button size="sm" variant="ghost" disabled={saving} onClick={() => setDraft(null)}>{pt ? "Descartar alterações" : "Discard changes"}</Button>}
                <Button asChild size="sm" variant="link" className="ml-auto"><Link to="/newsletter">{pt ? "Abrir feed" : "Open feed"}</Link></Button>
              </div>
            </>}
      </CardContent>
    </Card>
  );
}
