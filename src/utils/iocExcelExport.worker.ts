import ExcelJS from 'exceljs';
import { buildNewsExcelWorkbook, buildBulkExcelWorkbook, type NewsExcelPayload } from './iocExcelWorkbook';
import type { BulkRow } from './bulkEnrichment';
import { addOtPatchExcelCharts } from './otPatchExcelCharts';

const scope = self as unknown as {
  onmessage: (event: MessageEvent<NewsExcelPayload | { kind: 'bulk'; rows: BulkRow[] }>) => void;
  postMessage: (value: unknown, transfer?: Transferable[]) => void;
};
scope.onmessage = async event => {
  try {
    const bulk = 'kind' in event.data && event.data.kind === 'bulk';
    const workbook = bulk ? buildBulkExcelWorkbook(event.data.rows as BulkRow[], ExcelJS) : buildNewsExcelWorkbook(event.data as NewsExcelPayload, ExcelJS);
    let bytes = new Uint8Array(await workbook.xlsx.writeBuffer());
    if (!bulk && 'dataset' in event.data && ['ot-patches', 'ai-patches'].includes(event.data.dataset)) bytes = await addOtPatchExcelCharts(bytes, event.data);
    scope.postMessage({ buffer: bytes.buffer }, [bytes.buffer]);
  } catch (error) {
    scope.postMessage({ error: error instanceof Error ? error.message : 'Não foi possível gerar o arquivo Excel.' });
  }
};
