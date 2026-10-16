import { buildBulkExcelWorkbook, type NewsExcelPayload } from './iocExcelWorkbook';
import type { BulkRow } from './bulkEnrichment';
export { buildNewsExcelWorkbook, buildBulkExcelWorkbook, type NewsExcelPayload } from './iocExcelWorkbook';
const mime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

function download(buffer: ArrayBuffer, filename: string) {
  const url = URL.createObjectURL(new Blob([buffer], { type: mime }));
  const link = document.createElement('a'); link.href = url; link.download = filename;
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

export async function exportNewsExcel(payload: NewsExcelPayload, filename: string) {
  // ExcelJS ZIP generation can block the page for tens of seconds on large
  // inventories. Keep the workbook and compression off the UI thread.
  const worker = new Worker(new URL('./iocExcelExport.worker.ts', import.meta.url), { type: 'module' });
  const buffer = await new Promise<ArrayBuffer>((resolve, reject) => {
    const finish = (error?: Error, result?: ArrayBuffer) => {
      clearTimeout(timer); worker.terminate();
      if (error) reject(error); else resolve(result!);
    };
    const timer = setTimeout(() => finish(new Error('O Excel excedeu o tempo de preparação. Tente um período menor ou exporte em CSV.')), 120000);
    worker.onerror = event => { event.preventDefault(); finish(new Error('Falha ao preparar o Excel. Atualize a página e tente novamente; o CSV continua disponível.')); };
    worker.onmessageerror = () => finish(new Error('Falha ao receber o arquivo Excel. Tente novamente.'));
    worker.onmessage = event => {
      if (event.data?.error) finish(new Error(event.data.error));
      else if (event.data?.buffer instanceof ArrayBuffer) finish(undefined, event.data.buffer);
      else finish(new Error('Resposta de exportação inválida.'));
    };
    try { worker.postMessage(payload); } catch (error) { finish(error instanceof Error ? error : new Error('Falha ao enviar dados para o Excel.')); }
  });
  download(buffer, filename);
}
export async function exportBulkExcel(rows: BulkRow[]) {
  const { default: ExcelLib } = await import('exceljs');
  const wb = buildBulkExcelWorkbook(rows, ExcelLib);
  download(await wb.xlsx.writeBuffer() as ArrayBuffer, 'threatsumm4ry-bulk-' + new Date().toISOString().replace(/[:.]/g, '-') + '.xlsx');
}
