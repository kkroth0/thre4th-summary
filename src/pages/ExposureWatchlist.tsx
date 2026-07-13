import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, Clock, Loader2, Play, Plus, RefreshCw, Trash2 } from "lucide-react";
import { PageLayout } from "@/components/PageLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";
import {
  createExposureAsset, deleteExposureAsset, fetchExposureAssets, fetchExposureChanges,
  fetchExposureSnapshots, runExposureAsset, updateExposureAsset,
  type ExposureAsset, type ExposureAssetInput, type ExposureAssetType,
  type ExposureChange, type ExposureSnapshot,
} from "@/services/threatApi";
import { toast } from "sonner";

const emptyForm: ExposureAssetInput = {
  label: "", type: "domain", value: "", limit: 50, activeValidation: false, scheduleEnabled: true,
};

const riskTone: Record<string, string> = {
  critical: "border-destructive/40 bg-destructive/10 text-destructive",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-500",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-500",
  low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-500",
  info: "border-primary/40 bg-primary/10 text-primary",
  none: "border-border bg-muted text-muted-foreground",
};

const statusLabel = (status: string) => ({
  never_run: "Never run", running: "Running", success: "OK", error: "Error", config_error: "Config",
}[status] || status);

function Metric({ label, value }: { label: string; value: number }) {
  return <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p></CardContent></Card>;
}

export default function ExposureWatchlist() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [assets, setAssets] = useState<ExposureAsset[]>([]);
  const [changes, setChanges] = useState<ExposureChange[]>([]);
  const [snapshots, setSnapshots] = useState<ExposureSnapshot[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [form, setForm] = useState<ExposureAssetInput>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);

  const selectedAsset = useMemo(
    () => assets.find((asset) => asset.id === selectedAssetId) || null,
    [assets, selectedAssetId],
  );
  const totals = useMemo(() => assets.reduce((acc, asset) => {
    acc.services += asset.lastSummary?.totalServices || 0;
    acc.criticalHigh += asset.lastSummary?.criticalHighFindings || 0;
    if (["error", "config_error"].includes(asset.lastStatus)) acc.errors += 1;
    return acc;
  }, { services: 0, criticalHigh: 0, errors: 0 }), [assets]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [assetList, changeList] = await Promise.all([fetchExposureAssets(), fetchExposureChanges(100)]);
      setAssets(assetList);
      setChanges(changeList);
      setSelectedAssetId((current) => current || assetList[0]?.id || null);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Exposure Watchlist API error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    if (!selectedAssetId) { setSnapshots([]); return; }
    void fetchExposureSnapshots(selectedAssetId).then(setSnapshots).catch((error) => {
      toast.error(error instanceof Error ? error.message : "Snapshot API error");
    });
  }, [selectedAssetId]);

  const submit = async () => {
    try {
      const saved = editingId ? await updateExposureAsset(editingId, form) : await createExposureAsset(form);
      toast.success(pt ? "Ativo salvo" : "Asset saved");
      setForm(emptyForm); setEditingId(null); setSelectedAssetId(saved.id);
      await load();
    } catch (error) { toast.error(error instanceof Error ? error.message : "Failed to save asset"); }
  };
  const edit = (asset: ExposureAsset) => {
    setEditingId(asset.id);
    setForm({ label: asset.label, type: asset.type, value: asset.value, limit: asset.limit, activeValidation: asset.activeValidation, scheduleEnabled: asset.scheduleEnabled });
  };
  const runNow = async (asset: ExposureAsset) => {
    setBusyId(asset.id);
    try {
      await runExposureAsset(asset.id); await load();
      setSelectedAssetId(asset.id); setSnapshots(await fetchExposureSnapshots(asset.id));
      toast.success(pt ? "Snapshot finalizado" : "Snapshot complete");
    } catch (error) { toast.error(error instanceof Error ? error.message : "Snapshot failed"); }
    finally { setBusyId(null); }
  };
  const remove = async (asset: ExposureAsset) => {
    setBusyId(asset.id);
    try {
      await deleteExposureAsset(asset.id);
      if (selectedAssetId === asset.id) setSelectedAssetId(null);
      await load(); toast.success(pt ? "Ativo removido" : "Asset removed");
    } catch (error) { toast.error(error instanceof Error ? error.message : "Delete failed"); }
    finally { setBusyId(null); }
  };

  return <PageLayout>
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-4 py-6">
      <header className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div><h1 className="text-3xl font-bold tracking-tight">Exposure Watchlist</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{pt
            ? "Cadastre ativos externos, rode snapshots e acompanhe mudancas de servicos, CVEs, risco e validacao TCP."
            : "Save external assets, run snapshots, and track service, CVE, risk, and TCP validation changes."}</p></div>
        <Button variant="outline" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2 data-icon="inline-start" className="animate-spin" /> : <RefreshCw data-icon="inline-start" />}
          {pt ? "Atualizar" : "Refresh"}
        </Button>
      </header>

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Assets" value={assets.length} /><Metric label="Services" value={totals.services} />
        <Metric label="Critical / High" value={totals.criticalHigh} /><Metric label="Errors" value={totals.errors} />
      </section>

      <section className="grid gap-5 lg:grid-cols-[320px_1fr]">
        <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Plus />{editingId ? (pt ? "Editar ativo" : "Edit asset") : (pt ? "Novo ativo" : "New asset")}</CardTitle></CardHeader>
          <CardContent className="flex flex-col gap-4">
            <label className="flex flex-col gap-1.5"><Label>Label</Label><Input value={form.label} onChange={(event) => setForm({ ...form, label: event.target.value })} /></label>
            <label className="flex flex-col gap-1.5"><Label>Type</Label><Select value={form.type} onValueChange={(value) => setForm({ ...form, type: value as ExposureAssetType })}>
              <SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectGroup>
                <SelectItem value="domain">Domain</SelectItem><SelectItem value="ip">IP</SelectItem><SelectItem value="cidr">CIDR</SelectItem>
                <SelectItem value="asn">ASN</SelectItem><SelectItem value="shodan_query">Shodan query</SelectItem>
              </SelectGroup></SelectContent></Select></label>
            <label className="flex flex-col gap-1.5"><Label>Value</Label>{form.type === "shodan_query"
              ? <Textarea rows={3} value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} />
              : <Input value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} />}</label>
            <label className="flex flex-col gap-1.5"><Label>Limit</Label><Input type="number" min={1} max={100} value={form.limit} onChange={(event) => setForm({ ...form, limit: Number(event.target.value) || 50 })} /></label>
            <div className="flex items-center justify-between rounded-md border p-3"><Label>Daily snapshot</Label><Switch checked={form.scheduleEnabled} onCheckedChange={(value) => setForm({ ...form, scheduleEnabled: value })} /></div>
            <div className="flex flex-col gap-2 rounded-md border p-3"><div className="flex items-center justify-between"><Label>Active TCP</Label><Switch checked={form.activeValidation} onCheckedChange={(value) => setForm({ ...form, activeValidation: value })} /></div>
              <p className="text-xs text-muted-foreground">{pt ? "Somente pares IP/porta publicos observados pelos providers." : "Only provider-observed public IP/port pairs."}</p></div>
            <Button onClick={() => void submit()} disabled={!form.label.trim() || !form.value.trim()}>{editingId ? (pt ? "Salvar alteracoes" : "Save changes") : (pt ? "Adicionar ativo" : "Add asset")}</Button>
          </CardContent></Card>

        <Card className="min-w-0"><CardHeader><CardTitle className="text-base">Watchlist</CardTitle></CardHeader><CardContent className="overflow-x-auto p-0">
          <Table><TableHeader><TableRow><TableHead>Asset</TableHead><TableHead>Risk</TableHead><TableHead>Services</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader>
            <TableBody>{assets.map((asset) => <TableRow key={asset.id} className={cn(selectedAssetId === asset.id && "bg-muted/50")}>
              <TableCell><button className="text-left" onClick={() => setSelectedAssetId(asset.id)}><span className="block font-medium">{asset.label}</span><span className="block max-w-64 truncate text-xs text-muted-foreground">{asset.type} · {asset.value}</span></button></TableCell>
              <TableCell><Badge variant="outline" className={riskTone[asset.lastRisk || "none"]}>{asset.lastRisk || "none"}</Badge></TableCell>
              <TableCell>{asset.lastSummary?.totalServices || 0}</TableCell><TableCell><Badge variant="secondary">{statusLabel(asset.lastStatus)}</Badge></TableCell>
              <TableCell><div className="flex justify-end gap-1"><Button size="icon" variant="ghost" aria-label="Run snapshot" onClick={() => void runNow(asset)} disabled={busyId === asset.id}>{busyId === asset.id ? <Loader2 className="animate-spin" /> : <Play />}</Button>
                <Button size="sm" variant="ghost" onClick={() => edit(asset)}>{pt ? "Editar" : "Edit"}</Button><Button size="icon" variant="ghost" aria-label="Delete asset" onClick={() => void remove(asset)} disabled={busyId === asset.id}><Trash2 /></Button></div></TableCell>
            </TableRow>)}{assets.length === 0 ? <TableRow><TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">{pt ? "Nenhum ativo cadastrado." : "No assets saved."}</TableCell></TableRow> : null}</TableBody>
          </Table></CardContent></Card>
      </section>

      <section className="grid gap-5 lg:grid-cols-2">
        <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><AlertTriangle />{pt ? "Mudancas recentes" : "Recent changes"}</CardTitle></CardHeader><CardContent className="flex flex-col gap-2">
          {changes.slice(0, 12).map((change) => <article key={change.id} className="rounded-md border p-3"><div className="flex items-center justify-between gap-2"><Badge variant="outline" className={riskTone[change.severity]}>{change.severity}</Badge><time className="text-xs text-muted-foreground">{new Date(change.detectedAt).toLocaleString()}</time></div><p className="mt-2 text-sm font-medium">{change.title}</p><p className="text-xs text-muted-foreground">{change.description}</p></article>)}
          {changes.length === 0 ? <p className="py-8 text-center text-sm text-muted-foreground">{pt ? "Sem mudancas ainda." : "No changes yet."}</p> : null}
        </CardContent></Card>
        <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Clock />{selectedAsset?.label || (pt ? "Historico" : "History")}</CardTitle></CardHeader><CardContent className="flex flex-col gap-3">
          {selectedAsset?.lastError ? <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{selectedAsset.lastError}</p> : null}
          {snapshots.slice(0, 8).map((snapshot) => <article key={snapshot.id} className="rounded-md border p-3"><div className="flex items-center justify-between gap-2"><Badge variant="secondary">{snapshot.status}</Badge><time className="text-xs text-muted-foreground">{snapshot.completedAt ? new Date(snapshot.completedAt).toLocaleString() : "running"}</time></div><dl className="mt-3 grid grid-cols-3 gap-2 text-sm"><div><dt className="text-xs text-muted-foreground">Services</dt><dd className="font-semibold">{snapshot.summary.totalServices}</dd></div><div><dt className="text-xs text-muted-foreground">Critical/High</dt><dd className="font-semibold">{snapshot.summary.criticalHighFindings}</dd></div><div><dt className="text-xs text-muted-foreground">Changes</dt><dd className="font-semibold">{snapshot.changes.length}</dd></div></dl></article>)}
          {snapshots.length === 0 ? <p className="py-8 text-center text-sm text-muted-foreground">{pt ? "Selecione um ativo ou rode o primeiro snapshot." : "Select an asset or run the first snapshot."}</p> : null}
        </CardContent></Card>
      </section>
    </main>
  </PageLayout>;
}
