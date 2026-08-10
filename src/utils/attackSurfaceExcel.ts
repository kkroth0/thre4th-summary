import type ExcelJS from "exceljs";
import type { AttackSurfaceResponse } from "@/services/threatApi";
import {
  buildAttackSurfaceWorkbook,
  type AttackSurfaceExportOptions,
  type ExcelWorkbookFactory,
} from "@/utils/attackSurfaceExport";

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

export async function exportAttackSurfaceExcel(
  result: AttackSurfaceResponse,
  options: AttackSurfaceExportOptions = {},
): Promise<void> {
  const { default: ExcelLib } = await import("exceljs");
  const workbook = buildAttackSurfaceWorkbook(result, ExcelLib as ExcelWorkbookFactory, options);
  const buffer = await (workbook as ExcelJS.Workbook).xlsx.writeBuffer();
  triggerDownload(
    new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }),
    "AttackSurfaceShodan_ThreatSumm4ry.xlsx",
  );
}
