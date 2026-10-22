import manifest from '@/config/weeklyEyTemplate.json';
import type { WeeklyReportData } from '@/types/weekly-report';
export { buildWeeklySlides } from './weeklyEySlides';
export { createWeeklyPptx } from './weeklyPptxPackage';
import { createWeeklyPptx } from './weeklyPptxPackage';
export async function exportWeeklyPptx(report:WeeklyReportData){
 const response=await fetch(manifest.url);if(!response.ok)throw Error('Template indisponível');
 const blob=await createWeeklyPptx(report,await response.arrayBuffer());const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;
 const recipient=report.profile?.name?.replace(/[^\p{L}\p{N}]+/gu,'_')||'EY';a.download=`Boletim_Semanal_${recipient}_${report.range.id}_v${report.revision}.pptx`;
 a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
