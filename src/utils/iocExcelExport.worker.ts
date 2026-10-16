import ExcelJS from 'exceljs';
import { buildNewsExcelWorkbook, type NewsExcelPayload } from './iocExcelWorkbook';

const scope = self as unknown as {
  onmessage: (event: MessageEvent<NewsExcelPayload>) => void;
  postMessage: (value: unknown, transfer?: Transferable[]) => void;
};
scope.onmessage = async event => {
  try {
    const workbook = buildNewsExcelWorkbook(event.data, ExcelJS);
    const bytes = new Uint8Array(await workbook.xlsx.writeBuffer());
    scope.postMessage({ buffer: bytes.buffer }, [bytes.buffer]);
  } catch (error) {
    scope.postMessage({ error: error instanceof Error ? error.message : 'Não foi possível gerar o arquivo Excel.' });
  }
};
