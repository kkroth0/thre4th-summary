import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {buildBulkExcelWorkbook} from './iocExcelWorkbook';
import type {BulkRow} from './bulkEnrichment';
const Excel=createRequire(`${process.cwd()}/package.json`)('exceljs') as typeof import('exceljs');
test('unified presentation keeps publication links and catalog identities while omitting all operational diagnostics',async()=>{
 const row:BulkRow={query:'93.184.216.34',state:'partial',context:{publications:[],errors:[],entityResolutionVersion:'qa',entityResolutions:[{sourceKind:'actor',sourceLabel:'Actor alias',sourceId:'G0040',kind:'actor',name:'Patchwork',id:'G0040',verification:'catalog',catalogSource:'attack'}],evidence:[{provider:'Axur',title:'Research report',link:'https://cti.axur.com/insight/test',published:'2026-10-27T12:00:00Z',collectedAt:'2026-10-27T12:10:00Z',confidence:90,reputation:null,entities:[{kind:'actor',id:'G0040',name:'Actor alias',relation:'mentioned-by-source'}]}]},result:{query:'93.184.216.34',overallScore:0,threatLevel:'safe',totalVendors:1,detections:0,vendorData:[{name:'VirusTotal',data:{},error:'Unavailable'}]}};
 const wb=buildBulkExcelWorkbook([row],Excel);assert.equal(wb.getWorksheet('Indicadores')!.getRow(2).getCell('actors').value,'Patchwork');assert.equal(wb.getWorksheet('Relações')!.getRow(2).getCell('association').value,'Menção em publicação');
 const restored=new Excel.Workbook();await restored.xlsx.load(await wb.xlsx.writeBuffer());assert.equal(restored.getWorksheet('Publicações')!.getCell('H2').hyperlink,'https://cti.axur.com/insight/test');
 const text=JSON.stringify(restored.worksheets.flatMap(sheet=>sheet.getSheetValues()));for(const label of ['COBERTURA INCOMPLETA','CRITÉRIOS DE LEITURA','LEITURA DO LOTE','Unavailable','Consulta incompleta','Resumo executivo'])assert.ok(!text.includes(label));
 assert.equal(restored.getWorksheet('Indicadores')!.getCell('C2').value,'Sem evidência suficiente');
});
