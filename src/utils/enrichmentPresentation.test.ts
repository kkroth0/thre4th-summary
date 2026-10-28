import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { buildBulkExcelWorkbook } from './iocExcelWorkbook';
import type { BulkRow } from './bulkEnrichment';
const Excel = createRequire(`${process.cwd()}/package.json`)('exceljs') as typeof import('exceljs');
test('presentation keeps contextual mentions distinct from attribution with deduplicated dashboard counts',async()=>{
 const evidence = {provider:'Axur',title:'Report',link:'https://cti.axur.com/insight/test',published:'2026-10-27T12:00:00Z',collectedAt:'2026-10-27T12:10:00Z',confidence:90,reputation:null,
 entities:[{kind:'actor' as const,id:'actor-a',name:'Actor A',relation:'mentioned-with'}]};
 const row:BulkRow={query:'8.8.8.8',state:'partial',context:{publications:[],evidence:[evidence,{...evidence,title:'Second report'}],errors:[]},result:{query:'8.8.8.8',overallScore:0,threatLevel:'safe',totalVendors:2,detections:0,vendorData:[{name:'VirusTotal',data:{Status:'Clean'}},{name:'OTX',data:{},error:'Unavailable'}]}};
 const wb=buildBulkExcelWorkbook([row],Excel);
 assert.deepEqual(wb.worksheets.slice(0,2).map(s=>s.name),['Dashboard','Resumo executivo']);
 assert.equal(wb.getWorksheet('Dashboard')!.getCell('V5').value,1);
 assert.equal(wb.getWorksheet('Dashboard')!.getCell('J5').value,0);
 const relation=wb.getWorksheet('Relações')!;
 assert.equal(relation.getRow(2).getCell('relation').value,'mentioned-with');
 assert.equal(relation.getRow(2).getCell('link').hyperlink,evidence.link);
 assert.ok(JSON.stringify(wb.getWorksheet('Resumo executivo')!.getSheetValues()).includes('apenas citadas'));
 const restored=new Excel.Workbook();await restored.xlsx.load(await wb.xlsx.writeBuffer());
 assert.equal(restored.getWorksheet('Relações')!.getCell('H2').hyperlink,evidence.link);
 assert.equal(restored.getWorksheet('Indicadores')!.getCell('G5').value,'Parcial');
 assert.ok(restored.getWorksheet('Indicadores')!.autoFilter);
});
