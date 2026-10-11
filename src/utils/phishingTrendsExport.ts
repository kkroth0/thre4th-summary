import type ExcelJS from 'exceljs';
import { SHEET_TAB, scrubXml, styleHeaderRow, workbookMetadata } from './deckTemplate';
import type { PhishingDataset, PhishingReport } from '@/services/threatApi';

export interface ExcelWorkbookFactory { Workbook: new () => ExcelJS.Workbook }
const unknown = 'Não identificado';
const joined = (values: string[]) => values.length ? values.join('; ') : unknown;
const date = (iso: string) => iso && Number.isFinite(Date.parse(iso)) ? new Date(iso) : null;
const safeUrl = (value: string) => /^https?:\/\//i.test(value) ? value : '';
const groupBasis = { 'named-campaign': 'Campanha nomeada na fonte', 'correlated-story': 'Evento correlacionado', publication: 'Publicação sem correlação confirmada' };
const filterNames: Record<string, string> = { search: 'Busca', technique: 'Técnica', sector: 'Setor-alvo', region: 'Região-alvo', brand: 'Marca imitada', profileId: 'Perfil', nationState: 'Nation-state' };
const weekStart = (iso: string) => {
    const value = date(iso);
    if (!value) return null;
    value.setUTCHours(0, 0, 0, 0);
    value.setUTCDate(value.getUTCDate() - (value.getUTCDay() + 6) % 7);
    return value;
};

export function buildPhishingTrendsWorkbook(data: PhishingDataset, ExcelLib: ExcelWorkbookFactory): ExcelJS.Workbook {
    const wb = new ExcelLib.Workbook();
    workbookMetadata(wb, 'Campanhas de Phishing', new Date().toISOString(), 'phishing, campanhas, inteligência de ameaças');
    const table = (name: string, headers: [string, number][], rows: unknown[][]) => {
        let clean = name.replace(/[\\/*?:[\]]/g, ' ').trim().slice(0, 31) || 'Recorte';
        const base = clean;
        for (let i = 2; wb.worksheets.some(sheet => sheet.name.toLowerCase() === clean.toLowerCase()); i++) clean = `${base.slice(0, 26)} (${i})`;
        const sheet = wb.addWorksheet(clean, { properties: SHEET_TAB, views: [{ state: 'frozen', ySplit: 1 }] });
        sheet.columns = headers.map(([header, width]) => ({ header, width }));
        styleHeaderRow(sheet, 1, headers.length);
        sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: Math.max(1, rows.length + 1), column: headers.length } };
        for (const values of rows) {
            const row = sheet.addRow(values.map(value => typeof value === 'string' ? scrubXml(value) : value));
            row.alignment = { vertical: 'top', wrapText: true };
            row.eachCell(cell => { if (cell.value instanceof Date) cell.numFmt = 'yyyy-mm-dd'; });
        }
        return sheet;
    };
    const summary = data.summary;
    table('Resumo', [['Indicador', 45], ['Valor', 75]], [
        ['Período inicial', date(data.range.from || '')], ['Período final', date(data.range.to || '')],
        ['Publicações', summary.publications], ['Grupos de campanha / evento', summary.groups],
        ['Grupos com múltiplas publicações', summary.correlatedGroups], ['Publicações com técnica identificada', summary.withTechnique],
        ['Nation-state citado', summary.nationState], ['Alvos no Brasil', summary.brazil], ['TTPs distintos', summary.distinctTtps],
        ['Cobertura da exportação', data.truncated ? `${summary.publications} de ${data.total} publicações (limite atingido)` : 'Todas as publicações do recorte'],
        ['Filtros', Object.entries(data.filters).filter(([, value]) => value).map(([key, value]) => `${filterNames[key] || key}: ${key === 'profileId' ? data.facets.profiles.find(profile => profile.id === value)?.name || value : value}`).join('; ') || 'Nenhum filtro adicional'],
        ...summary.months.map(({ label, count }) => [`Publicações ${label}`, count]),
        ...summary.techniques.map(({ label, count }) => [`Técnica: ${label}`, count]),
    ]);
    const reportHeaders: [string, number][] = [
        ['ID', 19], ['Data publicação', 18], ['Mês', 12], ['Semana (início)', 18], ['Título', 65], ['Resumo', 85],
        ['Campanha (agrupamento)', 60], ['Categoria principal', 30], ['Técnica de phishing', 42], ['Vetor', 28],
        ['Setor-alvo', 30], ['Região', 30], ['Marca imitada', 28], ['Threat actor', 30], ['Nation-state', 25], ['Malware / Kit', 35],
        ['TTPs (MITRE ID)', 38], ['TTPs (nome)', 60], ['Táticas', 45], ['Fonte', 32], ['Tipo de fonte', 25], ['Link', 65],
        ['Recortes (abas)', 38], ['Base do agrupamento', 38], ['Evidências de extração', 100], ['Critério MITRE', 75],
    ];
    const campaignNames = new Map(data.campaigns.map(group => [group.id, group.name]));
    const reportValues = (row: PhishingReport): unknown[] => [
        row.id, date(row.pubDate), row.pubDate.slice(0, 7), weekStart(row.pubDate), row.title, row.description,
        campaignNames.get(row.groupId) || row.title, row.primaryTechnique || 'Phishing sem técnica identificada', joined(row.phishingTechniques), joined(row.vectors),
        joined(row.sectors), joined(row.regions), joined(row.brands), joined(row.actorNames), row.nationState === 'reported' ? 'Citado na fonte' : unknown, joined(row.software),
        joined(row.ttps.map(ttp => ttp.id)), joined(row.ttps.map(ttp => ttp.name || `${ttp.id}: nome indisponível`)), joined([...new Set(row.ttps.flatMap(ttp => ttp.tactics))]),
        row.source, row.sourceType, safeUrl(row.link), joined(row.profileMatches.map(match => match.profileName)), groupBasis[row.groupBasis],
        row.evidence.map(e => `${e.label} [${e.field}] "${e.term}": ${e.snippet}`).join('\n'),
        row.ttps.map(ttp => `${ttp.id}: ${ttp.basis === 'reported' ? 'Citado' : 'Inferido por regra'} — ${ttp.reason}`).join('\n'),
    ];
    table('Reports', reportHeaders, data.reports.map(reportValues));
    table('Campanhas', [
        ['Campanha / evento', 65], ['Base do agrupamento', 38], ['Primeira publicação', 20], ['Última publicação', 20], ['Reports', 12],
        ['Técnicas', 42], ['Vetor', 28], ['Threat actor', 30], ['Malware / Kit', 35], ['Marca imitada', 28], ['Setor-alvo', 30], ['Região', 30],
        ['TTPs (união)', 40], ['Resumo da fonte principal', 85], ['Fontes', 55], ['Link principal', 65], ['Todas as fontes (links)', 90],
    ], data.campaigns.map(group => [
        group.name, groupBasis[group.basis], date(group.firstPublished), date(group.lastPublished), group.reportCount,
        joined(group.techniques), joined(group.vectors), joined(group.actors), joined(group.software), joined(group.brands), joined(group.sectors), joined(group.regions),
        joined(group.ttpIds), group.description, joined(group.sources), safeUrl(group.links[0] || ''), group.links.map(safeUrl).filter(Boolean).join('\n'),
    ]));
    table('TTPs', [['ID MITRE', 18], ['Nome', 50], ['Táticas', 42], ['Reports', 12], ['Grupos', 12], ['Citado na fonte', 18], ['Inferido por regra', 20], ['MITRE link', 65]],
        data.ttps.map(ttp => [ttp.id, ttp.name || unknown, joined(ttp.tactics), ttp.reports, ttp.groups, ttp.reported, ttp.inferred, `https://attack.mitre.org/techniques/${ttp.id.replace('.', '/')}/`]));
    table('Fontes', [['Fonte', 45], ['Reports', 12]], summary.sources.map(row => [row.label || 'Fonte não informada', row.count]));
    const latam = new Set(['Brazil', 'Latin America', 'Mexico', 'Argentina', 'Chile', 'Colombia', 'Peru']);
    for (const [name, select] of [
        ['Brasil', (row: PhishingReport) => row.regions.includes('Brazil')],
        ['Latam', (row: PhishingReport) => row.regions.some(region => latam.has(region))],
    ] as const) table(name, [...reportHeaders, ['Motivo do recorte', 65]], data.reports.filter(select).map(row => [...reportValues(row), `Região-alvo extraída: ${joined(row.regions)}`]));
    for (const profile of data.facets.profiles) table(`Org - ${profile.name}`, [...reportHeaders, ['Motivo do recorte', 65]],
        data.reports.filter(row => row.profileMatches.some(match => match.profileId === profile.id)).map(row => [...reportValues(row), row.profileMatches.find(match => match.profileId === profile.id)!.reasons.join('; ')]));
    table('Premissas recortes', [['Critério', 35], ['Premissa', 110]], [
        ['Classificação', 'Regras contextuais em título, resumo e corpo disponível. Recomendações e treinamento não classificam incidentes. As evidências constam em Reports.'],
        ['Agrupamento', 'Campanha nomeada explicitamente ou ID de evento do correlacionador. Publicação sem vínculo fica separada. Mesma técnica, ator, fornecedor ou kit não confirma o mesmo evento.'],
        ['Resumo', 'Texto da publicação principal; não é uma síntese validada de todas as fontes.'],
        ['MITRE ATT&CK', 'IDs citados são separados de mapeamentos inferidos por regras. Inferência não confirma execução observada.'],
        ['Brasil / Latam', 'Região da vítima/alvo explicitamente descrita; país de origem do ator não define o recorte.'],
        ['Organizações', 'Relevância segundo setores, regiões, tecnologias, marcas e atores do perfil do usuário. Não significa que a organização foi vítima.'],
        ['Campos vazios', 'Não identificado significa ausência de evidência extraída, inclusive quando o texto completo não está disponível.'],
        ['Contagens', 'Publicações e grupos são unidades diferentes. Uma publicação pode conter múltiplas técnicas; soma de técnicas não representa publicações únicas.'],
        ...data.facets.profiles.map(profile => [`Perfil: ${profile.name}`, 'Recorte dinâmico do perfil cadastrado nesta conta; motivos por publicação na respectiva aba.']),
    ]);
    return wb;
}

export const phishingTrendsExcelFilename = (range: PhishingDataset['range'] = {}): string =>
    range.from && range.to ? `Campanhas_Phishing_${range.from}_a_${range.to}.xlsx` : `Campanhas_Phishing_${new Date().toISOString().slice(0, 10)}.xlsx`;

export async function exportPhishingTrendsExcel(data: PhishingDataset): Promise<void> {
    const { default: ExcelLib } = await import('exceljs');
    const buffer = await buildPhishingTrendsWorkbook(data, ExcelLib as ExcelWorkbookFactory).xlsx.writeBuffer();
    const url = URL.createObjectURL(new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = phishingTrendsExcelFilename(data.range);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
}
