// Download do JSON do boletim, e o nome de arquivo que os três formatos usam.
//
// Nem o PPTX nem o PDF são montados aqui. O deck do boletim é o template SRR, e
// template só se preenche com python-pptx (pptxgenjs desenha do zero, não abre
// um .pptx existente); o PDF é esse mesmo deck convertido. Os dois vêm prontos
// do worker na VPS e o site só baixa (threatApi.downloadBoletimDeck) — montar
// aqui produziria um documento parecido, nunca o da casa.
import type { BoletimJob } from '@/services/threatApi';

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

export function exportBoletimJSON(job: BoletimJob): void {
    const blob = new Blob([JSON.stringify(job.json, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${boletimFilename(job)}.json`;
    a.click();
    URL.revokeObjectURL(url);
}
