import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { ExternalLink, FileCode2, FilterX, Loader2, Pencil, Plus, Search, Trash2 } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/PageHeader";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import {
  createHunt, deleteHunt, fetchHearth, fetchHuntCoverage, fetchHuntFieldCoverage, fetchHunts,
  updateHunt, type FieldCoverage, type HearthHunt, type HuntInput, type HuntingItem,
  type PrivateHunt, type TechniqueCoverage, type TechniqueCoverageNode,
} from "@/services/threatApi";
import { filterHunts, huntOrigin, parseList } from "./huntingView";

type HuntForm = {
  title: string; hypothesis: string; tactics: string; techniques: string; cves: string;
  technologies: string; dataSources: string; query: string; notes: string;
  falsePositives: string; status: HuntInput["status"]; sourceReportId: string; hearthId: string;
};

const EMPTY_FORM: HuntForm = {
  title: "", hypothesis: "", tactics: "", techniques: "", cves: "", technologies: "",
  dataSources: "", query: "", notes: "", falsePositives: "", status: "draft",
  sourceReportId: "", hearthId: "",
};

const isHearth = (hunt: HuntingItem): hunt is HearthHunt => huntOrigin(hunt) === "hearth";
const formOf = (hunt: PrivateHunt): HuntForm => ({
  title: hunt.title, hypothesis: hunt.hypothesis, tactics: hunt.tactics.join(", "),
  techniques: hunt.techniques.join(", "), cves: hunt.cves.join(", "),
  technologies: hunt.technologies.join(", "), dataSources: hunt.dataSources.join(", "),
  query: hunt.query, notes: hunt.notes, falsePositives: hunt.falsePositives, status: hunt.status,
  sourceReportId: hunt.sourceReportId, hearthId: hunt.hearthId,
});
const inputOf = (form: HuntForm): HuntInput => ({
  title: form.title, hypothesis: form.hypothesis, tactics: parseList(form.tactics),
  techniques: parseList(form.techniques, true), cves: parseList(form.cves, true),
  technologies: parseList(form.technologies), dataSources: parseList(form.dataSources), query: form.query,
  notes: form.notes, falsePositives: form.falsePositives, status: form.status,
  sourceReportId: form.sourceReportId, hearthId: form.hearthId,
});

function FacetSelect({ label, value, options, onChange }: {
  label: string;
  value: string;
  options: { value: string; count: number }[];
  onChange: (value: string) => void;
}) {
  return (
    <div className="space-y-1.5">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger className="h-9" aria-label={label}><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value="all">Todos</SelectItem>
            {options.map((option) => (
              <SelectItem key={option.value} value={option.value}>{option.value} · {option.count}</SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  );
}

function HuntFormDialog({ form, editing, saving, onChange, onClose, onSave }: {
  form: HuntForm | null;
  editing: boolean;
  saving: boolean;
  onChange: (form: HuntForm) => void;
  onClose: () => void;
  onSave: () => void;
}) {
  if (!form) return null;
  const field = (key: keyof HuntForm) => ({
    value: form[key],
    onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange({ ...form, [key]: event.target.value }),
  });
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-h-[92vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? "Editar hunt" : "Nova hunt"}</DialogTitle>
          <DialogDescription>Hipótese operacional e consulta KQL privadas da sua conta.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="hunt-title">Título</Label>
            <Input id="hunt-title" autoFocus required {...field("title")} />
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="hunt-hypothesis">Hipótese</Label>
            <Textarea id="hunt-hypothesis" required rows={3} {...field("hypothesis")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hunt-tactics">Táticas</Label>
            <Input id="hunt-tactics" placeholder="Execution, Defense Evasion" {...field("tactics")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hunt-techniques">Técnicas ATT&CK</Label>
            <Input id="hunt-techniques" placeholder="T1059.001, T1218" {...field("techniques")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hunt-cves">CVEs</Label>
            <Input id="hunt-cves" placeholder="CVE-2026-12345" {...field("cves")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hunt-technologies">Tecnologias</Label>
            <Input id="hunt-technologies" placeholder="Microsoft Sentinel" {...field("technologies")} />
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="hunt-data-sources">Fontes de dados / tabelas</Label>
            <Input id="hunt-data-sources" placeholder="SigninLogs, DeviceEvents" {...field("dataSources")} />
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="hunt-query">Consulta KQL</Label>
            <Textarea id="hunt-query" rows={8} className="font-mono text-xs" placeholder="SigninLogs&#10;| where ..." {...field("query")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hunt-fp">Falsos positivos</Label>
            <Textarea id="hunt-fp" rows={3} {...field("falsePositives")} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="hunt-notes">Notas</Label>
            <Textarea id="hunt-notes" rows={3} {...field("notes")} />
          </div>
          <div className="space-y-1.5">
            <Label>Status</Label>
            <Select value={form.status} onValueChange={(status: HuntInput["status"]) => onChange({ ...form, status })}>
              <SelectTrigger aria-label="Status"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="draft">Rascunho</SelectItem>
                  <SelectItem value="ready">Pronta</SelectItem>
                  <SelectItem value="archived">Arquivada</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancelar</Button>
          <Button onClick={onSave} disabled={saving || !form.title.trim() || !form.hypothesis.trim()}>
            {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Salvar
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function HuntDetail({ hunt, onClose, onEdit, onCopy }: {
  hunt: HuntingItem | null;
  onClose: () => void;
  onEdit: (hunt: PrivateHunt) => void;
  onCopy: (hunt: HearthHunt) => void;
}) {
  if (!hunt) return null;
  const hearth = isHearth(hunt);
  const body = hearth ? hunt.why : hunt.hypothesis;
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <div className="flex flex-wrap items-center gap-2 pr-8">
            <Badge variant={hearth ? "secondary" : "default"}>{hearth ? "HEARTH" : "Sua hunt"}</Badge>
            <Badge variant="outline">{hearth ? hunt.category : hunt.status}</Badge>
          </div>
          <DialogTitle className="pt-2 text-xl leading-snug">{hunt.title}</DialogTitle>
          <DialogDescription>
            {hearth ? `Enviada por ${hunt.submitter.name || "comunidade HEARTH"}` : "Consulta privada da sua conta"}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-5 text-sm">
          <p className="whitespace-pre-wrap leading-relaxed">{body}</p>
          {!!hunt.techniques.length && (
            <div className="flex flex-wrap gap-1.5">{hunt.techniques.map((id) => <Badge key={id} variant="outline" className="font-mono">{id}</Badge>)}</div>
          )}
          {!hearth && hunt.query && (
            <pre className="overflow-x-auto rounded-md border bg-muted/50 p-4 text-xs"><code>{hunt.query}</code></pre>
          )}
          {(hearth ? hunt.notes : hunt.notes) && (
            <div><h3 className="mb-1 font-semibold">Notas</h3><p className="whitespace-pre-wrap text-muted-foreground">{hunt.notes}</p></div>
          )}
          {hearth && hunt.references && (
            <div><h3 className="mb-1 font-semibold">Referências</h3><p className="whitespace-pre-wrap break-words text-muted-foreground">{hunt.references}</p></div>
          )}
        </div>
        <DialogFooter>
          {hearth ? (
            <>
              <Button asChild variant="outline"><a href={hunt.sourceUrl} target="_blank" rel="noreferrer">Fonte <ExternalLink className="ml-2 h-4 w-4" /></a></Button>
              <Button onClick={() => onCopy(hunt)}>Usar como hipótese</Button>
            </>
          ) : <Button onClick={() => onEdit(hunt)}><Pencil className="mr-2 h-4 w-4" /> Editar</Button>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function FieldCoverageList({ coverage }: { coverage: FieldCoverage | null }) {
  if (!coverage?.values.length) return <p className="py-16 text-center text-sm text-muted-foreground">Nenhuma cobertura registrada nas suas hunts.</p>;
  const max = coverage.values[0].count;
  return (
    <div className="divide-y rounded-md border">
      {coverage.values.map((item) => (
        <div key={item.value} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-4 py-3">
          <div className="min-w-0">
            <div className="truncate text-sm font-medium">{item.value}</div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-muted"><div className="h-full bg-primary" style={{ width: `${(item.count / max) * 100}%` }} /></div>
          </div>
          <span className="font-mono text-xs text-muted-foreground">{item.count}</span>
        </div>
      ))}
    </div>
  );
}

function TechniqueMatrix({ coverage, hunts }: { coverage: TechniqueCoverage | null; hunts: PrivateHunt[] }) {
  const [selected, setSelected] = useState<TechniqueCoverageNode | null>(null);
  if (!coverage) return <div className="flex items-center gap-2 py-16 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Carregando cobertura…</div>;
  const related = selected ? hunts.filter((hunt) => hunt.techniques.some((id) => id === selected.id || id.startsWith(`${selected.id}.`))) : [];
  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4">
        <div><div className="text-2xl font-semibold tabular-nums">{coverage.covered} / {coverage.total}</div><p className="text-sm text-muted-foreground">técnicas e subtécnicas ATT&CK cobertas pelas suas hunts</p></div>
        <div className="flex gap-3 text-xs text-muted-foreground"><span>● coberta</span><span>◐ parcial</span><span>○ sem cobertura</span></div>
      </div>
      <div className="overflow-x-auto pb-3">
        <div className="flex min-w-max items-start gap-2">
          {coverage.tactics.map((tactic) => (
            <section key={tactic.id} className="w-56 shrink-0 rounded-md border bg-card">
              <header className="border-b p-3"><h3 className="text-sm font-semibold">{tactic.name}</h3><p className="mt-0.5 text-[11px] text-muted-foreground">{tactic.covered} / {tactic.total} técnicas</p></header>
              <div className="space-y-1 p-2">
                {tactic.techniques.map((technique) => (
                  <button
                    key={technique.id}
                    type="button"
                    onClick={() => setSelected(technique)}
                    className={`w-full rounded border px-2.5 py-2 text-left transition-colors hover:border-primary/50 ${
                      technique.state === "covered" ? "border-primary/40 bg-primary/10" : technique.state === "partial" ? "border-primary/30 bg-primary/5" : "border-transparent bg-muted/40"
                    }`}
                  >
                    <span className="block font-mono text-[10px] text-muted-foreground">{technique.id} · {technique.count || technique.subs.filter((sub) => sub.count).length}</span>
                    <span className="mt-0.5 block text-xs font-medium leading-snug">{technique.name}</span>
                  </button>
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
      {selected && (
        <div className="rounded-md border p-4">
          <div className="flex items-start justify-between gap-4"><div><div className="font-mono text-xs text-muted-foreground">{selected.id}</div><h3 className="font-semibold">{selected.name}</h3></div><Button size="sm" variant="ghost" onClick={() => setSelected(null)}>Fechar</Button></div>
          {!!selected.subs.length && <div className="mt-3 flex flex-wrap gap-1.5">{selected.subs.map((sub) => <Badge key={sub.id} variant={sub.count ? "default" : "outline"} className="font-mono text-[10px]">{sub.id} · {sub.count}</Badge>)}</div>}
          <div className="mt-4 space-y-2">
            {related.length ? related.map((hunt) => <div key={hunt.id} className="rounded bg-muted/50 px-3 py-2 text-sm">{hunt.title}</div>) : <p className="text-sm text-muted-foreground">Nenhuma hunt privada cobre esta técnica.</p>}
          </div>
        </div>
      )}
    </div>
  );
}

const Hunting = () => {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [searchParams] = useSearchParams();
  const prefilled = useRef(false);
  const [catalog, setCatalog] = useState<HearthHunt[]>([]);
  const [privateHunts, setPrivateHunts] = useState<PrivateHunt[]>([]);
  const [techCoverage, setTechCoverage] = useState<TechniqueCoverage | null>(null);
  const [technologyCoverage, setTechnologyCoverage] = useState<FieldCoverage | null>(null);
  const [dataSourceCoverage, setDataSourceCoverage] = useState<FieldCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [catalogError, setCatalogError] = useState(false);
  const [query, setQuery] = useState(() => searchParams.get("query") || "");
  const deferredQuery = useDeferredValue(query);
  const [showHearth, setShowHearth] = useState(true);
  const [showPrivate, setShowPrivate] = useState(true);
  const [category, setCategory] = useState("all");
  const [tactic, setTactic] = useState("all");
  const [technique, setTechnique] = useState("all");
  const [technology, setTechnology] = useState("all");
  const [dataSource, setDataSource] = useState("all");
  const [selected, setSelected] = useState<HuntingItem | null>(null);
  const [form, setForm] = useState<HuntForm | null>(null);
  const [editingId, setEditingId] = useState("");
  const [saving, setSaving] = useState(false);

  const refreshCoverage = useCallback(async () => {
    const [tech, technologies, dataSources] = await Promise.all([
      fetchHuntCoverage("technique"), fetchHuntFieldCoverage("technology"), fetchHuntFieldCoverage("dataSource"),
    ]);
    setTechCoverage(tech); setTechnologyCoverage(technologies); setDataSourceCoverage(dataSources);
  }, []);

  useEffect(() => {
    let live = true;
    Promise.allSettled([
      fetchHearth(), fetchHunts(), fetchHuntCoverage("technique"),
      fetchHuntFieldCoverage("technology"), fetchHuntFieldCoverage("dataSource"),
    ]).then(([hearth, own, tech, technologies, dataSources]) => {
      if (!live) return;
      if (hearth.status === "fulfilled") setCatalog(hearth.value.hunts); else setCatalogError(true);
      if (own.status === "fulfilled") setPrivateHunts(own.value); else toast.error(pt ? "Falha ao carregar suas hunts" : "Failed to load your hunts");
      if (tech.status === "fulfilled") setTechCoverage(tech.value);
      if (technologies.status === "fulfilled") setTechnologyCoverage(technologies.value);
      if (dataSources.status === "fulfilled") setDataSourceCoverage(dataSources.value);
      setLoading(false);
    });
    return () => { live = false; };
  }, [pt]);

  useEffect(() => {
    if (prefilled.current || searchParams.get("new") !== "1") return;
    prefilled.current = true;
    const title = searchParams.get("title") || "";
    setForm({
      ...EMPTY_FORM,
      title: title ? `Investigar: ${title}` : "",
      hypothesis: title ? `Investigar sinais relacionados ao relatório “${title}”.` : "",
      techniques: searchParams.get("techniques") || "",
      cves: searchParams.get("cves") || "",
      sourceReportId: searchParams.get("sourceReportId") || "",
    });
  }, [searchParams]);

  const allItems = useMemo<HuntingItem[]>(() => [...privateHunts, ...catalog], [privateHunts, catalog]);
  const facets = useMemo(() => {
    const build = (values: string[], hit: (hunt: HuntingItem, value: string) => boolean) => [...new Set(values.filter(Boolean))]
      .sort((a, b) => a.localeCompare(b))
      .map((value) => ({ value, count: allItems.filter((hunt) => hit(hunt, value)).length }));
    return {
      categories: build(catalog.map((hunt) => hunt.category), (hunt, value) => isHearth(hunt) && hunt.category === value),
      tactics: build(allItems.flatMap((hunt) => hunt.tactics || []), (hunt, value) => hunt.tactics.includes(value)),
      techniques: build(allItems.flatMap((hunt) => hunt.techniques || []), (hunt, value) => hunt.techniques.includes(value)),
      technologies: build(privateHunts.flatMap((hunt) => hunt.technologies), (hunt, value) => !isHearth(hunt) && hunt.technologies.includes(value)),
      dataSources: build(privateHunts.flatMap((hunt) => hunt.dataSources), (hunt, value) => !isHearth(hunt) && hunt.dataSources.includes(value)),
    };
  }, [allItems, catalog, privateHunts]);

  const origin = showHearth && showPrivate ? "all" : showHearth ? "hearth" : showPrivate ? "private" : "none";
  const shown = useMemo(() => filterHunts(allItems, {
    query: deferredQuery, origin, category, tactic, technique, technology, dataSource,
  }), [allItems, deferredQuery, origin, category, tactic, technique, technology, dataSource]);

  const openPrivate = (hunt: PrivateHunt) => { setSelected(null); setEditingId(hunt.id); setForm(formOf(hunt)); };
  const copyHearth = (hunt: HearthHunt) => {
    setSelected(null); setEditingId("");
    setForm({ ...EMPTY_FORM, title: hunt.title, hypothesis: hunt.title, tactics: hunt.tactics.join(", "), techniques: hunt.techniques.join(", "), notes: [hunt.why, hunt.notes].filter(Boolean).join("\n\n"), hearthId: hunt.id });
  };
  const save = async () => {
    if (!form) return;
    setSaving(true);
    try {
      const result = editingId ? await updateHunt(editingId, inputOf(form)) : await createHunt(inputOf(form));
      setPrivateHunts(result.items); setForm(null); setEditingId(""); await refreshCoverage();
      toast.success(pt ? "Hunt salva" : "Hunt saved");
    } catch (error) { toast.error((error as Error).message); }
    finally { setSaving(false); }
  };
  const remove = async (hunt: PrivateHunt) => {
    if (!window.confirm(pt ? `Apagar “${hunt.title}”?` : `Delete “${hunt.title}”?`)) return;
    try { setPrivateHunts(await deleteHunt(hunt.id)); await refreshCoverage(); }
    catch (error) { toast.error((error as Error).message); }
  };
  const clearFilters = () => { setQuery(""); setShowHearth(true); setShowPrivate(true); setCategory("all"); setTactic("all"); setTechnique("all"); setTechnology("all"); setDataSource("all"); };

  return (
    <PageLayout width="max-w-7xl">
      <PageHeader
        title="Hunting"
        subtitle={pt ? "Hipóteses públicas para explorar. Consultas KQL privadas para operar. Cobertura ATT&CK medida no que é seu." : "Public hypotheses to explore. Private KQL queries to operate. ATT&CK coverage measured on your own hunts."}
        actions={<Button onClick={() => { setEditingId(""); setForm({ ...EMPTY_FORM }); }}><Plus className="mr-2 h-4 w-4" /> {pt ? "Nova hunt" : "New hunt"}</Button>}
      />

      <Tabs defaultValue="library" className="space-y-5">
        <TabsList className="grid w-full max-w-sm grid-cols-2">
          <TabsTrigger value="library">Biblioteca <span className="ml-2 text-xs text-muted-foreground">{allItems.length}</span></TabsTrigger>
          <TabsTrigger value="coverage">Cobertura</TabsTrigger>
        </TabsList>

        <TabsContent value="library" className="space-y-4">
          <div className="relative max-w-2xl">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input aria-label={pt ? "Buscar hunts" : "Search hunts"} value={query} onChange={(event) => setQuery(event.target.value)} className="pl-9" placeholder={pt ? "Buscar hipótese, técnica, CVE, tecnologia ou tabela…" : "Search hypothesis, technique, CVE, technology, or table…"} />
          </div>
          {catalogError && <div className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">O catálogo HEARTH está indisponível; suas hunts continuam acessíveis.</div>}
          <div className="grid gap-5 lg:grid-cols-[240px_minmax(0,1fr)]">
            <aside className="h-fit space-y-5 rounded-md border bg-card p-4 lg:sticky lg:top-5">
              <div className="flex items-center justify-between"><h2 className="text-sm font-semibold">Filtros</h2><Button variant="ghost" size="icon" className="h-7 w-7" onClick={clearFilters} title="Limpar filtros"><FilterX className="h-4 w-4" /></Button></div>
              <fieldset className="space-y-2">
                <legend className="mb-2 text-xs text-muted-foreground">Origem</legend>
                <div className="flex items-center gap-2"><Checkbox id="origin-hearth" checked={showHearth} onCheckedChange={(value) => setShowHearth(Boolean(value))} /><Label htmlFor="origin-hearth" className="flex flex-1 justify-between text-sm"><span>HEARTH</span><span className="text-muted-foreground">{catalog.length}</span></Label></div>
                <div className="flex items-center gap-2"><Checkbox id="origin-private" checked={showPrivate} onCheckedChange={(value) => setShowPrivate(Boolean(value))} /><Label htmlFor="origin-private" className="flex flex-1 justify-between text-sm"><span>Suas hunts</span><span className="text-muted-foreground">{privateHunts.length}</span></Label></div>
              </fieldset>
              <FacetSelect label="Categoria" value={category} options={facets.categories} onChange={setCategory} />
              <FacetSelect label="Tática" value={tactic} options={facets.tactics} onChange={setTactic} />
              <FacetSelect label="Técnica" value={technique} options={facets.techniques} onChange={setTechnique} />
              <FacetSelect label="Tecnologia" value={technology} options={facets.technologies} onChange={setTechnology} />
              <FacetSelect label="Fonte de dados" value={dataSource} options={facets.dataSources} onChange={setDataSource} />
            </aside>

            <section className="min-w-0">
              <div className="mb-2 flex items-center justify-between text-sm text-muted-foreground"><span>{shown.length === allItems.length ? `${shown.length} hunts` : `${shown.length} / ${allItems.length}`}</span><span>HEARTH · MIT</span></div>
              {loading ? (
                <div className="flex items-center gap-2 py-20 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Carregando biblioteca…</div>
              ) : !shown.length ? (
                <div className="rounded-md border border-dashed py-20 text-center text-sm text-muted-foreground">Nenhuma hunt corresponde aos filtros.</div>
              ) : (
                <div className="rounded-md border bg-card">
                  <Table className="min-w-[820px]">
                    <TableHeader><TableRow><TableHead>Hipótese</TableHead><TableHead>ATT&CK</TableHead><TableHead>Cobertura</TableHead><TableHead className="w-28 text-right">Ações</TableHead></TableRow></TableHeader>
                    <TableBody>
                      {shown.map((hunt) => {
                        const hearth = isHearth(hunt);
                        return (
                          <TableRow key={`${huntOrigin(hunt)}-${hunt.id}`} style={{ contentVisibility: "auto", containIntrinsicSize: "64px" }}>
                            <TableCell className="max-w-xl py-3">
                              <button type="button" className="line-clamp-2 text-left text-sm font-medium leading-snug hover:text-primary" onClick={() => setSelected(hunt)}>{hunt.title}</button>
                              <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
                                <Badge variant={hearth ? "secondary" : "default"} className="text-[9px]">{hearth ? "HEARTH" : "SUA"}</Badge>
                                <span>{hearth ? [hunt.category, hunt.submitter.name].filter(Boolean).join(" · ") : hunt.status}</span>
                              </div>
                            </TableCell>
                            <TableCell className="py-3"><div className="flex max-w-52 flex-wrap gap-1">{hunt.techniques.slice(0, 3).map((id) => <Badge key={id} variant="outline" className="font-mono text-[10px]">{id}</Badge>)}{hunt.techniques.length > 3 && <Badge variant="outline">+{hunt.techniques.length - 3}</Badge>}</div></TableCell>
                            <TableCell className="py-3 text-xs text-muted-foreground">{hearth ? hunt.tactics.slice(0, 2).join(" · ") : [...hunt.technologies, ...hunt.dataSources].slice(0, 2).join(" · ") || "—"}</TableCell>
                            <TableCell className="py-3 text-right">
                              <div className="flex justify-end gap-1">
                                <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setSelected(hunt)} title="Abrir"><FileCode2 className="h-4 w-4" /></Button>
                                {!hearth && <><Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => openPrivate(hunt)} title="Editar"><Pencil className="h-4 w-4" /></Button><Button variant="ghost" size="icon" className="h-8 w-8 hover:text-destructive" onClick={() => remove(hunt)} title="Apagar"><Trash2 className="h-4 w-4" /></Button></>}
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </section>
          </div>
        </TabsContent>

        <TabsContent value="coverage">
          <Tabs defaultValue="technique" className="space-y-5">
            <TabsList>
              <TabsTrigger value="technique">MITRE ATT&CK</TabsTrigger>
              <TabsTrigger value="technology">Tecnologias</TabsTrigger>
              <TabsTrigger value="dataSource">Fontes de dados</TabsTrigger>
            </TabsList>
            <TabsContent value="technique"><TechniqueMatrix coverage={techCoverage} hunts={privateHunts} /></TabsContent>
            <TabsContent value="technology"><FieldCoverageList coverage={technologyCoverage} /></TabsContent>
            <TabsContent value="dataSource"><FieldCoverageList coverage={dataSourceCoverage} /></TabsContent>
          </Tabs>
        </TabsContent>
      </Tabs>

      <HuntDetail hunt={selected} onClose={() => setSelected(null)} onEdit={openPrivate} onCopy={copyHearth} />
      <HuntFormDialog form={form} editing={Boolean(editingId)} saving={saving} onChange={setForm} onClose={() => { setForm(null); setEditingId(""); }} onSave={save} />
    </PageLayout>
  );
};

export default Hunting;
