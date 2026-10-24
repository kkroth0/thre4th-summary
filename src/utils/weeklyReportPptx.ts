import type { WeeklyReportData } from '@/types/weekly-report';
import { createThreatSumm4ryWeeklyPptx, weeklyBrandFilename } from './weeklyThreatSumm4ry';
// Legacy layout helpers are retained for historical exports, not the website's download.
export { buildWeeklySlides } from './weeklyTemplateSlides';
export { createThreatSumm4ryWeeklyPptx as createWeeklyPptx } from './weeklyThreatSumm4ry';
export async function exportWeeklyPptx(report:WeeklyReportData){
 if(report.editorial?.status!=='ready')throw Error('Redija o boletim a partir das fontes antes de exportar.');
 const blob=await createThreatSumm4ryWeeklyPptx(report);const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;
 a.download=weeklyBrandFilename(report);
 a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
