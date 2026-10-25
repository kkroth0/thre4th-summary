import { ArrowRight, Check, FileText, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { WeeklyReportData } from '@/types/weekly-report';

interface Props {
  report: WeeklyReportData;
  newsCount: number;
  aiCount: number;
  dirty: boolean;
  saving: boolean;
  pt: boolean;
  onSave: () => void;
  onWrite: () => void;
  onReview: () => void;
}

export function WeeklyEditionWorkflow({ report, newsCount, aiCount, dirty, saving, pt, onSave, onWrite, onReview }: Props) {
  const l = (a: string, b: string) => pt ? a : b;
  const confirmed = report.selection.mode === 'manual' && !dirty;
  const hasSelection = newsCount + aiCount > 0;
  const writing = !!report.editorial?.active;
  const ready = confirmed && report.editorial?.status === 'ready';
  const canWrite = confirmed && hasSelection && report.editorial?.available && !writing && !ready;
  const steps = [
    { title: l('Selecionar notícias', 'Select stories'), detail: confirmed ? l('Seleção salva', 'Selection saved') : l('Revise as sugestões e salve', 'Review suggestions and save'), done: confirmed, active: !confirmed },
    { title: l('Preparar a redação', 'Prepare the draft'), detail: writing ? `${report.editorial?.completed || 0}/${report.editorial?.total || 0} ${l('matérias', 'stories')}` : ready ? l('Pronta para sua revisão', 'Ready for your review') : l('Texto e análise das fontes', 'Writing and source analysis'), done: ready, active: confirmed && !ready },
    { title: l('Revisar e exportar', 'Review and export'), detail: ready ? l('PowerPoint disponível em Exportar', 'PowerPoint available in Export') : l('JSON disponível a qualquer momento', 'JSON available at any time'), done: false, active: ready },
  ];

  return <aside aria-label={l('Preparar edição', 'Prepare edition')} className="order-first self-start rounded-xl border bg-card sm:grid sm:grid-cols-[1fr_auto] xl:sticky xl:top-6 xl:order-last xl:block">
    <div className="p-4 xl:border-b xl:p-5">
      <div className="flex items-center gap-2"><FileText className="h-4 w-4 text-primary" /><h2 className="font-semibold">{l('Sua edição', 'Your edition')}</h2></div>
      <p aria-live="polite" className="mt-1 text-xs text-muted-foreground">{dirty ? l('Alterações não salvas', 'Unsaved changes') : writing ? l('Redação em andamento', 'Writing in progress') : ready ? l('Pronta para revisão', 'Ready for review') : l('Rascunho do boletim global', 'Global bulletin draft')}</p>
      <div className="mt-3 flex flex-wrap gap-4 xl:mt-5 xl:block xl:space-y-4">{[[newsCount, 10, l('Notícias gerais', 'General news')], [aiCount, 5, l('Inteligência artificial', 'Artificial intelligence')]].map(([count, limit, label]) => <div key={label} className="min-w-[115px]">
        <div className="mb-2 flex justify-between gap-2 text-xs"><span className="text-muted-foreground">{label}</span><span className="font-medium tabular-nums">{count}<span className="text-muted-foreground"> / {limit}</span></span></div>
        <div className="hidden h-1 overflow-hidden rounded-full bg-muted xl:block"><div className="h-full rounded-full bg-primary transition-all" style={{ width: `${Math.min(100, Number(count) / Number(limit) * 100)}%` }} /></div>
      </div>)}</div>
    </div>
    <ol className="hidden space-y-5 p-5 xl:block">{steps.map((step, index) => <li key={step.title} className="flex gap-3" aria-current={step.active ? 'step' : undefined}>
      <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-semibold ${step.done ? 'border-primary/20 bg-primary/10 text-primary' : step.active ? 'border-primary bg-primary text-primary-foreground' : 'text-muted-foreground'}`}>{step.done ? <Check className="h-3.5 w-3.5" /> : index + 1}</span>
      <div><p className={`text-sm font-medium ${!step.active && !step.done ? 'text-muted-foreground' : ''}`}>{step.title}</p><p className="mt-1 text-xs leading-5 text-muted-foreground">{step.detail}</p></div>
    </li>)}</ol>
    <div className="border-t p-4 sm:max-w-[260px] sm:border-l sm:border-t-0 xl:max-w-none xl:border-l-0 xl:border-t xl:p-5">
      <Button className="w-full gap-2" size="sm" disabled={saving || writing || !hasSelection || (confirmed && !ready && !canWrite)} onClick={ready ? onReview : confirmed ? onWrite : onSave}>
        {(saving || writing) ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        {writing ? l('Redigindo…', 'Writing…') : ready ? l('Revisar redação', 'Review draft') : confirmed ? l('Gerar redação', 'Generate draft') : l('Salvar seleção', 'Save selection')}
        {!writing && !saving && <ArrowRight className="h-3.5 w-3.5" />}
      </Button>
      <p className="mt-3 text-xs leading-5 text-muted-foreground">{!hasSelection ? l('Escolha ao menos uma notícia para preparar a edição.', 'Choose at least one story to prepare the edition.') : !confirmed ? l('Suas escolhas serão preservadas nas próximas atualizações.', 'Updates will preserve your choices.') : !report.editorial?.available ? l('A redação por IA está indisponível. O JSON continua disponível em Exportar.', 'AI writing is unavailable. JSON remains available in Export.') : ready ? l('Confira os textos e as fontes antes de exportar.', 'Check the text and sources before exporting.') : l('O próximo passo usa o conteúdo das fontes selecionadas.', 'The next step uses the selected source content.')}</p>
      {confirmed && !ready && <button onClick={onReview} className="mt-3 text-xs font-medium text-primary hover:underline">{l('Ver detalhes da redação', 'View draft details')}</button>}
    </div>
  </aside>;
}
