// Exportadores do boletim gerado (PDF / JSON). O JSON continua sendo o formato
// de origem; aqui ele vira documento pronto pra circular. As libs pesadas
// (jspdf, jspdf-autotable) são tipos aqui e import dinâmico lá dentro, pra rota
// da workstation não carregar nada disso à toa.
//
// O PPTX NÃO é montado aqui: o deck do boletim é o template SRR, e template só
// se preenche com python-pptx — pptxgenjs desenha do zero e não abre um .pptx
// existente. Quem preenche é o worker na VPS, e o site só baixa o resultado
// (threatApi.downloadBoletimDeck).
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

export function exportBoletimJSON(job: BoletimJob): void {
    const blob = new Blob([JSON.stringify(job.json, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${boletimFilename(job)}.json`;
    a.click();
    URL.revokeObjectURL(url);
}
