import type ExcelJS from "exceljs";
import type { AttackSurfaceResponse } from "@/services/threatApi";
import { buildAttackSurfaceWorkbook, type ExcelWorkbookFactory } from "@/utils/attackSurfaceExport";

const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");

const triggerDownload = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

export async function exportAttackSurfaceExcel(result: AttackSurfaceResponse): Promise<void> {
  const { default: ExcelLib } = await import("exceljs");
  const workbook = buildAttackSurfaceWorkbook(result, ExcelLib as ExcelWorkbookFactory);
  const buffer = await (workbook as ExcelJS.Workbook).xlsx.writeBuffer();
  triggerDownload(
    new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }),
    `ThreatSumm4ry-Attack-Surface-${stamp()}.xlsx`,
  );
}
