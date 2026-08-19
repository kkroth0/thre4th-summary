// Exportadores do boletim gerado (PDF / PPTX). O JSON continua sendo o formato
// de origem; aqui ele vira documento pronto pra circular. As libs pesadas
// (jspdf, jspdf-autotable, pptxgenjs) são tipos aqui e import dinâmico lá
// dentro, pra rota da workstation não carregar nada disso à toa.
import type PptxGenJS from 'pptxgenjs';
import type { BoletimJob, BoletimReport } from '@/services/threatApi';
import {
    DECK, FONT_LIGHT, contentSlide, deckMetadata, deckText, scrubXml, type PptxFactory,
} from './deckTemplate';

// Só o PDF tem paleta própria; o PPTX segue o template do time (deckTemplate).
const COLORS = { blue: '1565C0', navy: '172033' } as const;
const rgb = (hex: string): [number, number, number] => [0, 2, 4].map((o) => parseInt(hex.substr(o, 2), 16)) as [number, number, number];

export const boletimFilename = (job: BoletimJob) => {
    const name = (job.json?.titulo || job.title || job.url || 'boletim')
        .normalize('NFKD').replace(/[^\w\s-]/g, '').trim().toLowerCase().replace(/[\s_-]+/g, '-').slice(0, 50);
    return `boletim-${job.type}-${name || 'boletim'}`;
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
// Mesmo padrão dos decks de Patch Tuesday e SAP: o boletim usa o template do
// time (deckTemplate.ts) em vez de um layout próprio — painel escuro sobre a
// arte, título amarelo sobre a régua em degradê, Franklin Gothic e o rodapé com
// data, página e a linha do time.
//
// Sem capa: o deck abre direto na primeira seção, com o título do boletim numa
// linha discreta logo abaixo da régua pra dizer de qual boletim se trata. A
// placa do canto inferior direito continua vazia, como nos outros decks — quem
// apresenta coloca a própria marca ali, nenhuma logo é embutida.
export type { PptxFactory };

// Um bloco vira quantos slides forem necessários: seção comprida quebra em
// "(cont.)" em vez de transbordar pra fora do painel. Os limites são menores
// que os do layout antigo porque a tela do template é 10 × 5.625in, não 13.3.
const BULLETS_PER_SLIDE = 8;
const TABLE_ROWS_PER_SLIDE = 9;

// Área útil dentro do painel: começa abaixo da régua e para antes do rodapé.
const BODY = { x: 0.5, w: 8.95, bottom: 4.9 } as const;

const chunk = <T,>(items: T[], size: number): T[][] =>
    items.length ? Array.from({ length: Math.ceil(items.length / size) }, (_, i) => items.slice(i * size, i * size + size)) : [];

// Colunas proporcionais ao conteúdo: um SHA-256 na coluna "Valor" não pode
// receber a mesma largura de "Tipo", senão a linha quebra em quatro e a tabela
// transborda o painel. O piso mantém a coluna curta legível.
export const colWidths = (head: string[], rows: string[][], total: number, min = 0.7): number[] => {
    const chars = head.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] || '').length)));
    const sum = chars.reduce((a, b) => a + b, 0) || 1;
    const raw = chars.map((c) => Math.max(min, (c / sum) * total));
    const scale = total / raw.reduce((a, b) => a + b, 0);
    return raw.map((w) => w * scale);
};

export function buildBoletimPresentation(job: BoletimJob, PptxLib: PptxFactory): PptxGenJS {
    const report = job.json;
    if (!report) throw new Error('Relatório sem conteúdo');

    const pptx = new PptxLib();
    // A data do rodapé é a da publicação da fonte; caindo pra geração do boletim.
    const date = report.source_published || report.generated_at || job.createdAt || null;
    deckMetadata(pptx, 'Boletim de Ameaças', date);
    const titulo = scrubXml(report.titulo || job.title || job.url);
    pptx.title = titulo;
    pptx.subject = subtitle(job);

    let page = 0;
    const newSlide = (title: string): PptxGenJS.Slide => {
        const slide = contentSlide(pptx, title, ++page, date);
        if (page === 1) {
            deckText(slide, [titulo, subtitle(job)].filter(Boolean).join(' · '), {
                x: BODY.x, y: 1.06, w: BODY.w, h: 0.22,
                fontFace: FONT_LIGHT, fontSize: 9, italic: true, color: DECK.muted,
            });
        }
        return slide;
    };
    // Só o primeiro slide carrega a linha do título, então só ele começa mais embaixo.
    const bodyTop = () => (page === 1 ? 1.36 : 1.16);

    for (const part of scrubXml(boletimSections(report))) {
        for (const block of part.blocks) {
            if (block.kind === 'table') {
                chunk(block.rows, TABLE_ROWS_PER_SLIDE).forEach((rows, index) => {
                    const slide = newSlide(index ? `${part.title} (cont.)` : part.title);
                    slide.addTable([
                        block.head.map((cell) => ({ text: cell, options: { bold: true, color: DECK.ink, fill: { color: DECK.accent } } })),
                        ...rows.map((row) => row.map((cell) => ({ text: cell, options: { color: DECK.white, fill: { color: DECK.card } } }))),
                    ], {
                        x: BODY.x, y: bodyTop(), w: BODY.w, colW: colWidths(block.head, rows, BODY.w),
                        fontFace: FONT_LIGHT, fontSize: 8, margin: 0.04, valign: 'middle',
                        border: { type: 'solid', color: DECK.cardLine, pt: 0.5 },
                        autoPage: false,
                    });
                });
                continue;
            }
            const items = block.kind === 'text' ? [block.text] : block.items;
            chunk(items, block.kind === 'text' ? 1 : BULLETS_PER_SLIDE).forEach((group, index) => {
                const slide = newSlide(index ? `${part.title} (cont.)` : part.title);
                const y = bodyTop();
                deckText(
                    slide,
                    group.map((item) => ({ text: item, options: { bullet: block.kind === 'bullets', breakLine: true } })),
                    {
                        x: BODY.x, y, w: BODY.w, h: BODY.bottom - y,
                        fontFace: FONT_LIGHT, fontSize: block.kind === 'text' ? 12 : 11,
                        color: DECK.white, lineSpacingMultiple: 1.2, valign: 'top',
                        paraSpaceAfter: block.kind === 'bullets' ? 6 : 0,
                    }
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
