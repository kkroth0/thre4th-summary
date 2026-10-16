import { useState } from 'react';
import { Download, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import { newsExportRange } from '@/utils/newsExport';

const localDay = (date: Date) => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;

export function NewsExportDialog({ pt, view }: { pt: boolean; view: string }) {
  const [open, setOpen] = useState(false);
  const [from, setFrom] = useState(() => localDay(new Date(Date.now() - 7 * 86400000)));
  const [to, setTo] = useState(() => localDay(new Date()));
  const [dataset, setDataset] = useState('news');
  const [format, setFormat] = useState('xlsx');
  const [busy, setBusy] = useState(false);
  const l = (a: string, b: string) => pt ? a : b;
  let valid = true;
  try { newsExportRange(from, to); } catch { valid = false; }

  const download = async () => {
    setBusy(true);
    try {
      const effectiveDataset = view === 'iocs' ? 'iocs' : dataset;
      const query = new URLSearchParams({ ...newsExportRange(from, to), dataset: effectiveDataset, format: format === 'xlsx' ? 'json' : format });
      const response = await fetch(`${view === 'iocs' ? '/api/intelligence/export' : '/api/news/export'}?${query}`, { cache: 'no-store' });
      if (!response.ok) {
        const error = await response.json().catch(() => null);
        throw new Error(error?.error || l('Não foi possível exportar o histórico.', 'Could not export the archive.'));
      }
      const filename = `threatsumm4ry-${effectiveDataset}-${from}-${to}.${format}`;
      if (format === 'xlsx') {
        const { exportNewsExcel } = await import('@/utils/iocExcelExport');
        await exportNewsExcel(await response.json(), filename);
      } else {
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      toast.success(l('Exportação baixada.', 'Export downloaded.'));
      setOpen(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : l('Falha ao exportar.', 'Export failed.'));
    } finally { setBusy(false); }
  };

  return <Dialog open={open} onOpenChange={value => { if (busy) return; setOpen(value); if (value) setDataset(view === 'posts' ? 'news' : 'iocs'); }}>
    <DialogTrigger asChild><Button variant="outline" size="sm" className="h-9 gap-1.5 px-3 text-xs"><Download className="h-3.5 w-3.5" />{l('Exportar por período', 'Export by date')}</Button></DialogTrigger>
    <DialogContent className="max-w-lg">
      <DialogHeader><DialogTitle>{l('Exportar notícias e IOCs', 'Export news and IOCs')}</DialogTitle><DialogDescription>{view === 'iocs' ? l('Exporte as evidências da base unificada no período, incluindo notícias e fontes externas disponíveis na sua conta.', 'Export unified inventory evidence for this period, including news and external sources available to your account.') : l('Baixe o histórico coletado no período, conforme os fornecedores monitorados. Inclui todas as páginas de resultados.', 'Download the collected archive for this period, respecting monitored vendors. Includes every result page.')}</DialogDescription></DialogHeader>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2"><Label htmlFor="news-export-from">{l('Data inicial', 'Start date')}</Label><Input id="news-export-from" type="date" value={from} onInput={event => setFrom(event.currentTarget.value)} onChange={event => setFrom(event.target.value)} /></div>
        <div className="space-y-2"><Label htmlFor="news-export-to">{l('Data final', 'End date')}</Label><Input id="news-export-to" type="date" value={to} onInput={event => setTo(event.currentTarget.value)} onChange={event => setTo(event.target.value)} /></div>
      </div>
      <p className="text-xs text-muted-foreground">{l('Os dias completos usam seu horário local. Quando a fonte não informa a publicação, usamos a data da primeira coleta, identificada no arquivo.', 'Full days use your local time. If publication time is unavailable, the first collection date is used and identified in the file.')}</p>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2"><Label htmlFor="news-export-dataset">{l('Conteúdo', 'Content')}</Label><select id="news-export-dataset" className="h-10 w-full rounded-md border bg-background px-3 text-sm" disabled={view === 'iocs'} value={view === 'iocs' ? 'iocs' : dataset} onChange={event => setDataset(event.target.value)}><option value="news">{l('Notícias', 'News')}</option><option value="iocs">IOCs</option></select></div>
        <div className="space-y-2"><Label htmlFor="news-export-format">{l('Formato', 'Format')}</Label><select id="news-export-format" className="h-10 w-full rounded-md border bg-background px-3 text-sm" value={format} onChange={event => setFormat(event.target.value)}><option value="xlsx">Excel (.xlsx)</option><option value="csv">CSV</option><option value="json">JSON</option></select></div>
      </div>
      <p className="rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">{dataset === 'iocs' ? l('IPs, domínios, hashes e URLs, com a notícia, fonte, data e entidades citadas em cada evidência.', 'IPs, domains, hashes and URLs, with publication, source, date and mentioned entities for each evidence record.') : l('Título, link, fonte, data, categorias, CVEs, atores, malware e indicadores extraídos.', 'Title, link, source, date, categories, CVEs, actors, malware and extracted indicators.')}</p>
      {!valid && <p role="alert" className="text-xs text-destructive">{l('Informe um período válido; a data final não pode preceder a inicial.', 'Enter a valid range; the end date cannot precede the start.')}</p>}
      {busy && <p role="status" className="text-xs text-muted-foreground">{l('Preparando todas as evidências do período. Arquivos grandes podem levar alguns segundos.', 'Preparing all evidence for this period. Large files may take a few seconds.')}</p>}
      <Button onClick={download} disabled={busy || !valid} className="gap-2">{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}{busy ? l('Preparando arquivo…', 'Preparing file…') : l('Baixar arquivo', 'Download file')}</Button>
    </DialogContent>
  </Dialog>;
}
