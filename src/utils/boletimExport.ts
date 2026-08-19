// Exportadores do boletim gerado (PDF / PPTX). O JSON continua sendo o formato
// de origem; aqui ele vira documento pronto pra circular. As libs pesadas
// (jspdf, jspdf-autotable, pptxgenjs) são tipos aqui e import dinâmico lá
// dentro, pra rota da workstation não carregar nada disso à toa.
import type PptxGenJS from 'pptxgenjs';
import type { BoletimJob, BoletimReport } from '@/services/threatApi';

const COLORS = { blue: '1565C0', navy: '172033', slate: '526274', border: 'DCE3EE', white: 'FFFFFF' } as const;
const rgb = (hex: string): [number, number, number] => [0, 2, 4].map((o) => parseInt(hex.substr(o, 2), 16)) as [number, number, number];

// Nome da casa, o MESMO que o motor gera (url_report.srr_filename): título
// legível, com acentos e espaços, sem os caracteres que o Windows recusa em nome
// de arquivo. Os dois lados precisam bater — o analista baixa o JSON aqui e o
// deck vem do motor, e os dois sentam lado a lado na mesma pasta.
const SRR_PREFIX = 'SRR - Surface Risk Report';

export const boletimFilename = (job: BoletimJob) => {
    const title = (job.json?.titulo || job.title || job.url || '').trim();
    const name = `${SRR_PREFIX} - ${title}`
        .replace(/^[\s-]+|[\s-]+$/g, '')          // título vazio deixa só o prefixo
        // eslint-disable-next-line no-control-regex
        .replace(/[<>:"/\\|?*\u0000-\u001f]/g, '')
        .replace(/\s+/g, ' ')
        .trim().replace(/[.\s]+$/, '')            // Windows recusa ponto/espaço no fim
        .slice(0, 120)
        .trim().replace(/[.\s]+$/, '');
    return name || SRR_PREFIX;
};

// ---- Estrutura comum ------------------------------------------------------
// PDF e PPTX renderizam a MESMA lista de seções: o que entra no documento é
// decidido uma vez só, então os dois formatos nunca divergem.
export type Block =
    | { kind: 'text'; text: string }
    | { kind: 'bullets'; items: string[] }
    | { kind: 'table'; head: string[]; rows: string[][] };
export type ReportSection = { title: string; blocks: Block[] };

const filled = (value?: string) => !!value && value.trim() && value.trim() !== 'N/A' && value.trim() !== 'Não informado';
const text = (value?: string): Block[] => (filled(value) ? [{ kind: 'text', text: value!.trim() }] : []);
const bullets = (items?: string[]): Block[] => {
    const list = (items || []).map((item) => String(item).trim()).filter(Boolean);
    return list.length ? [{ kind: 'bullets', items: list }] : [];
};
const section = (title: string, blocks: Block[]): ReportSection[] => (blocks.length ? [{ title, blocks }] : []);

const surfaceRows = (surface: BoletimReport['superficie_de_ataque']): string[] => {
    if (!surface) return [];
    if (Array.isArray(surface)) {
        return surface.filter((row) => row.tecnologia)
            .map((row) => `${row.tecnologia}: ${[row.categoria, row.utilizacao].filter(Boolean).join(' — ')}`);
    }
    return ([
        ['Vetor inicial', surface.vetor_inicial], ['Superfície', surface.superficie],
        ['Ativos alvo', surface.ativos_alvo], ['TTPs principais', surface.ttps_principais],
        ['Perfil das vítimas', surface.perfil_vitimas],
    ] as [string, string | undefined][]).filter(([, value]) => filled(value)).map(([label, value]) => `${label}: ${value}`);
};

export function boletimSections(report: BoletimReport): ReportSection[] {
    const r = report || {};
    const ator = r.ator || {};
    const atorLines = ([
        ['Ator', ator.threat_actor], ['Tipo', ator.tipo], ['Motivação', ator.motivation],
        ['Setores', (ator.sectors || []).join(', ')], ['Origem', ator.origem],
        ['Nível de atividade', ator.nivel_atividade], ['Diferencial', ator.diferencial],
    ] as [string, string | undefined][]).filter(([, value]) => filled(value)).map(([label, value]) => `${label}: ${value}`);

    return [
        ...section('Sumário executivo', text(r.sumario_executivo)),
        ...section('Estado de exploração', text(r.estado_exploracao)),
        ...section('Objetivo da campanha', text(r.objetivo)),
        ...section('Descrição', text(r.descricao)),
        ...section('Ator da ameaça', bullets(atorLines)),
        ...section('Tecnologias afetadas', (r.tecnologias_afetadas || []).length ? [{
            kind: 'table',
            head: ['Produto', 'Versão', 'Corrigida', 'CVE', 'CVSS'],
            rows: (r.tecnologias_afetadas || []).map((t) => [
                [t.fabricante, t.software].filter(Boolean).join(' ') || '—',
                t.versao || '—', filled(t.versao_corrigida) ? t.versao_corrigida! : '—',
                filled(t.cve) ? t.cve! : '—',
                [filled(t.cvss) ? t.cvss : '', t.severidade, t.kev ? 'KEV' : ''].filter(Boolean).join(' · ') || '—',
            ]),
        }] : []),
        ...section('Superfície de ataque', bullets(surfaceRows(r.superficie_de_ataque))),
        ...section('Pré-requisitos de exploração', bullets(r.pre_requisitos)),
        ...section('Impactos', bullets(r.impactos)),
        ...section('Recomendações', (r.recomendacoes || []).flatMap<Block>((group) => [
            ...text(group.titulo), ...bullets(group.itens),
        ])),
        ...section('Indicadores de comprometimento', (r.iocs || []).length ? [{
            kind: 'table',
            head: ['Categoria', 'Tipo', 'Valor'],
            rows: (r.iocs || []).map((ioc) => [ioc.categoria || '—', ioc.tipo || '—', ioc.valor || '—']),
        }] : []),
        ...section('MITRE ATT&CK', bullets((r.mitre_ttps || []).map((t) => [t.id, t.nome].filter(Boolean).join(' — ')))),
        ...section('Referências', bullets((r.referencias_coletadas || []).map((ref) => ref.url || ref.titulo || '').filter(Boolean))),
    ];
}

const subtitle = (job: BoletimJob) => {
    const r = job.json || {};
    return [r.cve_id, r.tlp ? `TLP:${r.tlp}` : '', job.type === 'vuln' ? 'Vulnerabilidade' : 'Campanha']
        .filter(Boolean).join(' · ');
};

// ---- PDF ------------------------------------------------------------------
export async function exportBoletimPDF(job: BoletimJob): Promise<void> {
    const report = job.json;
    if (!report) throw new Error('Relatório sem conteúdo');
    const [{ jsPDF }, { default: autoTable }] = await Promise.all([import('jspdf'), import('jspdf-autotable')]);

    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 14;
    const width = pageW - margin * 2;

    doc.setFillColor(...rgb(COLORS.navy));
    doc.rect(0, 0, pageW, 46, 'F');
    doc.setFillColor(...rgb(COLORS.blue));
    doc.rect(0, 46, pageW, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text(doc.splitTextToSize(report.titulo || job.title || job.url, width).slice(0, 2), margin, 20);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(203, 213, 225);
    doc.text(subtitle(job), margin, 38);
    if (report.source_url) doc.text(report.source_url.slice(0, 80), pageW - margin, 38, { align: 'right' });

    let y = 58;
    // Quebra de página manual: cada bloco pede o espaço que precisa antes de
    // desenhar. Sem isso o texto sai por baixo da margem.
    const room = (need: number) => { if (y + need > pageH - margin) { doc.addPage(); y = margin + 6; } };

    for (const part of boletimSections(report)) {
        room(16);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(11);
        doc.setTextColor(...rgb(COLORS.blue));
        doc.text(part.title.toUpperCase(), margin, y);
        y += 6;
        doc.setTextColor(...rgb(COLORS.navy));

        for (const block of part.blocks) {
            if (block.kind === 'table') {
                autoTable(doc, {
                    startY: y,
                    head: [block.head],
                    body: block.rows,
                    styles: { fontSize: 7, cellPadding: 1.5, overflow: 'linebreak' },
                    headStyles: { fillColor: rgb(COLORS.navy), textColor: 255 },
                    margin: { left: margin, right: margin },
                });
                y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;
                continue;
            }
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
            const lines = block.kind === 'text'
                ? doc.splitTextToSize(block.text, width)
                : block.items.flatMap((item) => doc.splitTextToSize(`•  ${item}`, width - 3));
            for (const line of lines) {
                room(6);
                doc.text(line, block.kind === 'text' ? margin : margin + 3, y);
                y += 4.6;
            }
            y += 3;
        }
        y += 2;
    }

    doc.save(`${boletimFilename(job)}.pdf`);
}

// ---- PPTX -----------------------------------------------------------------
export type PptxFactory = new () => PptxGenJS;

// Um bloco vira quantos slides forem necessários: seção comprida quebra em
// "(cont.)" em vez de transbordar pra fora do slide.
const BULLETS_PER_SLIDE = 9;
const TABLE_ROWS_PER_SLIDE = 12;

const slideTitle = (slide: PptxGenJS.Slide, title: string) =>
    slide.addText(title, { x: .55, y: .35, w: 12.2, h: .5, fontSize: 22, bold: true, color: COLORS.navy });

const chunk = <T,>(items: T[], size: number): T[][] =>
    items.length ? Array.from({ length: Math.ceil(items.length / size) }, (_, i) => items.slice(i * size, i * size + size)) : [];

export function buildBoletimPresentation(job: BoletimJob, PptxLib: PptxFactory): PptxGenJS {
    const report = job.json;
    if (!report) throw new Error('Relatório sem conteúdo');
    const pptx = new PptxLib();
    pptx.defineLayout({ name: 'BOLETIM', width: 13.333, height: 7.5 });
    pptx.layout = 'BOLETIM';
    pptx.author = 'ThreatSumm4ry';
    pptx.title = report.titulo || job.title || 'Boletim';
    pptx.subject = subtitle(job);
    pptx.defineSlideMaster({
        title: 'PADRAO',
        background: { color: COLORS.white },
        objects: [
            { rect: { x: 0, y: 0, w: 13.333, h: .08, fill: { color: COLORS.blue }, line: { color: COLORS.blue } } },
            { text: { text: report.source_url || '', options: { x: .45, y: 7.08, w: 8, h: .25, fontSize: 8, color: COLORS.slate } } },
        ],
        slideNumber: { x: 12.35, y: 7.08, w: .5, h: .25, fontSize: 8, color: COLORS.slate },
    });

    const cover = pptx.addSlide();
    cover.background = { color: COLORS.navy };
    cover.addText(report.titulo || job.title || job.url, { x: .7, y: 2.2, w: 12, h: 1.4, fontSize: 30, bold: true, color: COLORS.white, valign: 'top' });
    cover.addText(subtitle(job), { x: .7, y: 3.8, w: 12, h: .4, fontSize: 16, color: COLORS.blue });
    if (report.source_url) cover.addText(report.source_url, { x: .7, y: 6.4, w: 12, h: .3, fontSize: 10, color: COLORS.slate, hyperlink: { url: report.source_url } });

    for (const part of boletimSections(report)) {
        for (const block of part.blocks) {
            if (block.kind === 'table') {
                chunk(block.rows, TABLE_ROWS_PER_SLIDE).forEach((rows, index) => {
                    const slide = pptx.addSlide({ masterName: 'PADRAO' });
                    slideTitle(slide, index ? `${part.title} (cont.)` : part.title);
                    slide.addTable([
                        block.head.map((cell) => ({ text: cell, options: { bold: true, color: COLORS.white, fill: { color: COLORS.blue } } })),
                        ...rows.map((row) => row.map((cell) => ({ text: cell }))),
                    ], { x: .55, y: 1.1, w: 12.2, fontSize: 10, margin: .05, valign: 'middle', border: { type: 'solid', color: COLORS.border, pt: .5 }, color: COLORS.navy });
                });
                continue;
            }
            const items = block.kind === 'text' ? [block.text] : block.items;
            chunk(items, block.kind === 'text' ? 1 : BULLETS_PER_SLIDE).forEach((group, index) => {
                const slide = pptx.addSlide({ masterName: 'PADRAO' });
                slideTitle(slide, index ? `${part.title} (cont.)` : part.title);
                slide.addText(
                    group.map((item) => ({ text: item, options: { bullet: block.kind === 'bullets', breakLine: true } })),
                    { x: .7, y: 1.15, w: 11.9, h: 5.6, fontSize: block.kind === 'text' ? 15 : 14, color: COLORS.navy, valign: 'top' },
                );
            });
        }
    }

    return pptx;
}

export async function exportBoletimPPTX(job: BoletimJob): Promise<void> {
    const { default: PptxGenLib } = await import('pptxgenjs');
    const pptx = buildBoletimPresentation(job, PptxGenLib);
    await pptx.writeFile({ fileName: `${boletimFilename(job)}.pptx` });
}

export function exportBoletimJSON(job: BoletimJob): void {
    const blob = new Blob([JSON.stringify(job.json, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${boletimFilename(job)}.json`;
    a.click();
    URL.revokeObjectURL(url);
}
