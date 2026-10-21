import { useState } from "react";
import { Loader2, Pencil } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogTrigger } from "@/components/ui/dialog";
import { renderBoletimVersion, type BoletimJob } from "@/services/threatApi";

const tag = /^\[(POTENCIAL|EM EXPLORAÇÃO)\]\s*/;

export function ReportReviewDialog({ job, pt, onQueued }: { job: BoletimJob; pt: boolean; onQueued?: (job: BoletimJob) => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [recommendations, setRecommendations] = useState<{ titulo: string; text: string }[]>([]);
  const [techniques, setTechniques] = useState<{ id: string; nome: string; status: string; context: string }[]>([]);
  const prepare = (next: boolean) => {
    if (next && job.json) {
      setTitle(job.json.titulo || job.title);
      setSummary(job.json.sumario_executivo || "");
      setRecommendations((job.json.recomendacoes || []).map(group => ({ titulo: group.titulo || "Recomendações", text: (group.itens || []).join("\n") })));
      setTechniques((job.json.mitre_ttps || []).filter(t => t.id).map(t => ({
        id: t.id!, nome: t.nome || t.id!, status: t.contexto?.match(tag)?.[1] || "POTENCIAL",
        context: (t.contexto || `Avaliar ${t.nome || t.id} no cenário analisado; uso não confirmado nas fontes.`).replace(tag, ""),
      })));
    }
    setOpen(next);
  };
  const save = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const next = await renderBoletimVersion(job.id, {
        titulo: title, sumario_executivo: summary,
        ...(recommendations.length ? { recomendacoes: recommendations.map(group => ({ titulo: group.titulo, itens: group.text.split("\n").map(text => text.trim()).filter(Boolean) })) } : {}),
        ...(techniques.length ? { mitre_ttps: techniques.map(t => ({ id: t.id, contexto: `[${t.status}] ${t.context.trim()}` })) } : {}),
      });
      onQueued?.(next);
      setOpen(false);
      toast.success(pt ? "Nova versão na fila. A análise original foi preservada." : "New version queued. The original analysis was preserved.");
    } catch (error) { toast.error((error as Error).message); }
    finally { setBusy(false); }
  };
  return <Dialog open={open} onOpenChange={next => { if (!busy) prepare(next); }}>
    <DialogTrigger asChild><Button variant="outline" size="sm" className="gap-1.5"><Pencil className="h-3.5 w-3.5" />{pt ? "Revisar" : "Review"}</Button></DialogTrigger>
    <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
      <DialogHeader><DialogTitle>{pt ? "Revisar antes de exportar" : "Review before exporting"}</DialogTitle><DialogDescription>{pt ? "Salve uma nova versão com os ajustes. Os slides serão montados sem repetir a coleta ou chamar a IA." : "Save a new version with your edits. Slides are rebuilt without collecting sources or calling AI again."}</DialogDescription></DialogHeader>
      <div className="space-y-4">
        <div className="space-y-1.5"><Label htmlFor="review-title">{pt ? "Título" : "Title"}</Label><Input id="review-title" value={title} maxLength={300} onChange={e => setTitle(e.target.value)} disabled={busy} /></div>
        <div className="space-y-1.5"><Label htmlFor="review-summary">{pt ? "Resumo executivo" : "Executive summary"}</Label><Textarea id="review-summary" rows={6} maxLength={16000} value={summary} onChange={e => setSummary(e.target.value)} disabled={busy} /></div>
        {recommendations.map((group, index) => <div className="space-y-1.5" key={index}><Label htmlFor={`review-rec-${index}`}>{group.titulo}</Label><Textarea id={`review-rec-${index}`} rows={3} value={group.text} disabled={busy} onChange={e => setRecommendations(current => current.map((item, i) => i === index ? { ...item, text: e.target.value } : item))} /><p className="text-xs text-muted-foreground">{pt ? "Uma recomendação por linha." : "One recommendation per line."}</p></div>)}
        {techniques.length > 0 && <fieldset className="space-y-3"><legend className="mb-2 text-sm font-medium">MITRE ATT&CK</legend><p className="text-xs text-muted-foreground">{pt ? "Confirme EM EXPLORAÇÃO apenas após conferir as fontes. Mudanças de classificação ficam identificadas como revisão manual." : "Confirm observed use only after checking sources. Classification edits are identified as manual review."}</p>{techniques.map((t, index) => <div key={t.id} className="space-y-2 rounded-md border p-3">
          <Label htmlFor={`review-ttp-${index}`}>{t.id} · {t.nome}</Label>
          <select className="h-9 w-full rounded-md border bg-background px-2 text-sm" aria-label={`${pt ? "Classificação de" : "Classification for"} ${t.id}`} value={t.status} disabled={busy} onChange={e => setTechniques(current => current.map((item, i) => i === index ? { ...item, status: e.target.value } : item))}><option value="POTENCIAL">[POTENCIAL]</option><option value="EM EXPLORAÇÃO">[EM EXPLORAÇÃO]</option></select>
          <Textarea id={`review-ttp-${index}`} value={t.context} rows={3} maxLength={1400} disabled={busy} onChange={e => setTechniques(current => current.map((item, i) => i === index ? { ...item, context: e.target.value } : item))} />
        </div>)}</fieldset>}
      </div>
      <DialogFooter><Button variant="outline" disabled={busy} onClick={() => setOpen(false)}>{pt ? "Cancelar" : "Cancel"}</Button><Button disabled={busy || !title.trim() || !summary.trim() || techniques.some(t => !t.context.trim())} onClick={() => void save()}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}{pt ? "Salvar versão e gerar slides" : "Save version and build slides"}</Button></DialogFooter>
    </DialogContent>
  </Dialog>;
}
