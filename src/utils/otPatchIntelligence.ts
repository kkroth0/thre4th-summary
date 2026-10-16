import type { OtPatchRow, OtPatchData } from '../services/otPatchApi';

export interface OtReportContext {
  domain?: 'ot' | 'ai';
  sources?: OtPatchData['sources'];
  status?: OtPatchData['status'];
  filters?: { manufacturer: string; matching: string; remediation: string; query: string };
}
export interface OtAssessment {
  row: OtPatchRow; priority: 'P1' | 'P2' | 'P3' | 'P4'; priorityLabel: string;
  cvss: number | null; epss: number | null; kev: boolean; modelMatches: string[];
  reason: string; applicability: string; action: string; patchLabel: string;
}
const finite = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= max;
const unique = (values: string[]) => [...new Set(values.filter(Boolean))];
export const percentPt = (value: number) => (value * 100).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + '%';
export const OT_PRIORITY_LABELS = { P1: 'Exploração conhecida', P2: 'Alta prioridade técnica', P3: 'Avaliação necessária', P4: 'Acompanhamento' };
export const OT_PRIORITY_CRITERIA = [
  ['P1', 'Sinal de exploração conhecida no KEV ou no aviso do fabricante.'],
  ['P2', 'Sem sinal KEV; maior CVSS informado ≥ 7,0 ou maior EPSS disponível ≥ 50%.'],
  ['P3', 'Sem critérios anteriores; CVSS entre 4,0 e 6,9 ou severidade ainda não informada.'],
  ['P4', 'Sem critérios anteriores; CVSS informado abaixo de 4,0.'],
];
export function assessOtPatch(input: Record<string, unknown> | OtPatchRow, domain: 'ot' | 'ai' = 'ot'): OtAssessment {
  const row = { ...input, cves: Array.isArray(input.cves) ? input.cves : [], products: Array.isArray(input.products) ? input.products : [], matches: Array.isArray(input.matches) ? input.matches : [], cveSignals: Array.isArray(input.cveSignals) ? input.cveSignals : [], remediations: Array.isArray(input.remediations) ? input.remediations : [], vendors: Array.isArray(input.vendors) ? input.vendors : [], references: Array.isArray(input.references) ? input.references : [] } as OtPatchRow;
  const scores = [row.cvss, ...row.cveSignals.map(v => v.cvss)].filter(v => finite(v, 10));
  const probabilities = row.cveSignals.map(v => v.epss).filter(v => finite(v, 1));
  const cvss = scores.length ? Math.max(...scores) : null, epss = probabilities.length ? Math.max(...probabilities) : null;
  const kev = row.kev === true || row.cveSignals.some(v => v.kev === true);
  const priority = kev ? 'P1' : (cvss != null && cvss >= 7) || (epss != null && epss >= 0.5) ? 'P2' : cvss == null || cvss >= 4 ? 'P3' : 'P4';
  const modelMatches = unique(row.matches.flatMap(m => m.level === 'model' ? m.models || [] : []));
  const shownModels = modelMatches.slice(0, 4).join(', ').slice(0, 350);
  const modelLabel = shownModels + (modelMatches.length > 4 || shownModels.length < modelMatches.slice(0, 4).join(', ').length ? '; lista completa em Produtos e versões e na base técnica' : '');
  const signals = [kev ? 'Há sinal de exploração conhecida em pelo menos uma CVE do aviso.' : '', cvss != null ? `Maior CVSS informado: ${cvss.toFixed(1).replace('.', ',')}.` : 'Severidade técnica ainda não informada.', epss != null ? `Maior EPSS disponível: ${percentPt(epss)}.` : 'EPSS não disponível para esta seleção.', modelMatches.length ? `O catálogo contém modelo citado: ${modelLabel}.` : ''];
  let applicability = modelMatches.length ? `Modelo citado no catálogo: ${modelLabel}. Conferir a versão instalada e as condições do aviso antes de concluir aplicabilidade.`
    : row.matches.length ? 'Correspondência somente de fabricante. O modelo e a versão instalados ainda precisam ser confrontados com o aviso.'
      : 'Sem correspondência explícita com o catálogo de referência. Verificar se os produtos afetados fazem parte do ambiente.';
  const patchLabel = row.patch === 'available' ? 'Correção publicada' : row.patch === 'mitigation' ? 'Mitigação sem correção confirmada' : 'Correção não confirmada';
  let action = row.patch === 'available' ? 'Validar produto e versão; homologar a atualização indicada pelo fabricante e planejar a janela operacional. Registrar a verificação após a mudança.'
    : row.patch === 'mitigation' ? 'Validar produto e versão; avaliar e aplicar as medidas compensatórias indicadas pelo fabricante. Acompanhar a disponibilização de correção.'
      : 'Confirmar o estado da correção no aviso oficial e avaliar as orientações de proteção disponíveis. Manter acompanhamento até haver uma solução validada.';
  if (domain === 'ai') {
    applicability = applicability.replace(/Modelo/g, 'Pacote').replace(/modelo/g, 'pacote').replace(/fabricante/g, 'ferramenta');
    action = action.replace(/fabricante/g, 'mantenedor').replace('janela operacional', 'implantação e reversão');
  }
  return { row, priority, priorityLabel: OT_PRIORITY_LABELS[priority], cvss, epss, kev, modelMatches, reason: signals.filter(Boolean).join(' ').replace(domain === 'ai' ? /modelo/g : /$^/, 'pacote'), applicability, action, patchLabel };
}
export function analyzeOtReport(rows: Record<string, unknown>[], context?: OtReportContext) {
  const assessments = rows.map(row => assessOtPatch(row, context?.domain)).sort((a, b) => a.priority.localeCompare(b.priority) || Number(b.modelMatches.length > 0) - Number(a.modelMatches.length > 0) || (b.cvss ?? -1) - (a.cvss ?? -1) || (b.epss ?? -1) - (a.epss ?? -1) || String(a.row.id).localeCompare(String(b.row.id)));
  const priorities = Object.keys(OT_PRIORITY_LABELS).map(key => ({ label: key, count: assessments.filter(a => a.priority === key).length }));
  const vendorCounts = new Map<string, number>();
  for (const a of assessments) for (const vendor of unique(a.row.vendors)) vendorCounts.set(vendor, (vendorCounts.get(vendor) || 0) + 1);
  const vendors = [...vendorCounts].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  const sources = context?.sources || (Array.isArray(rows[0]?.sourceCoverage) ? rows[0].sourceCoverage as OtPatchData['sources'] : []);
  const partial = Boolean(context?.status && (!context.status.initialized || context.status.pending || context.status.failed || context.status.persistenceError)) || sources.some(s => s.status !== 'ok');
  return {
    assessments, priorities, vendors, sources, partial,
    total: assessments.length, cves: unique(assessments.flatMap(a => a.row.cves)).length,
    kev: assessments.filter(a => a.kev).length, fixes: assessments.filter(a => a.row.patch === 'available').length,
    mitigations: assessments.filter(a => a.row.patch === 'mitigation').length,
    unconfirmed: assessments.filter(a => !['available', 'mitigation'].includes(a.row.patch)).length,
    matched: assessments.filter(a => a.modelMatches.length > 0).length,
    missingCvss: assessments.filter(a => a.cvss == null).length, missingEpss: assessments.filter(a => a.epss == null).length,
    sourcesKnown: sources.length > 0, sourcesOk: sources.filter(s => s.status === 'ok').length,
  };
}
