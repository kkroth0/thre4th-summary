import test from 'node:test';
import assert from 'node:assert/strict';
import ExcelJS from 'exceljs';
import fs from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import unzipper from 'unzipper';
import {createBulkRawTable, BULK_WORKSHEET_HYPERLINK_LIMIT} from '../bulkRawTable.js';

const colors={teal:'FF077F80',ink:'FF111827',pale:'FFF5F6F7'};
async function fixture({hyperlinkLimit=2,rowLimit=1048576,records}) {
  const dir=fs.mkdtempSync(path.join(tmpdir(),'bulk-sheet-limits-')),file=path.join(dir,'fixture.xlsx'),locations=[];
  try {
    const wb=new ExcelJS.stream.xlsx.WorkbookWriter({filename:file,useStyles:true,useSharedStrings:false});
    const columns=[['indicator','Indicador',20],['link','Referência',45],['payload','Dados',40]];
    const table=createBulkRawTable(wb,'Evidências',columns,{colors,hyperlinkLimit,rowLimit,
      header(ws,columns){ws.columns=columns.map(([key,header,width])=>({key,header,width}));return ws.getRow(1);},
      valuesFor:async(values,sheet,row)=>{locations.push({sheet,row});return values;},
    });
    for (const record of records) await table.add(record);
    table.finish();await wb.commit();
    const zip=await unzipper.Open.file(file),read=async name=>(await zip.files.find(part=>part.path===name).buffer()).toString();
    const sheets=[];
    for (const part of zip.files.filter(part=>/^xl\/worksheets\/sheet\d+\.xml$/.test(part.path))) {
      const xml=await read(part.path);
      sheets.push({xml,links:(xml.match(/<hyperlink\s/g)||[]).length,rows:(xml.match(/<row\s/g)||[]).length});
    }
    return {locations,sheets,workbook:await read('xl/workbook.xml')};
  }finally{const target=path.resolve(dir);assert.ok(target.startsWith(path.resolve(tmpdir())+path.sep+'bulk-sheet-limits-'));fs.rmSync(target,{recursive:true,force:true});}
}
test('streamed evidence is split before Excel hyperlink limits and keeps physical overflow locations',async()=>{
  const records=Array.from({length:5},(_,i)=>({indicator:'qa-'+i,link:'https://example.com/report/'+i,payload:'saved-'+i}));
  const result=await fixture({records});
  assert.deepEqual(result.sheets.map(sheet=>sheet.links),[2,2,1]);
  assert.deepEqual(result.locations,[{sheet:'Evidências',row:2},{sheet:'Evidências',row:3},{sheet:'Evidências 2',row:2},{sheet:'Evidências 2',row:3},{sheet:'Evidências 3',row:2}]);
  for(let i=0;i<records.length;i++)assert.equal(result.sheets.reduce((n,sheet)=>n+(sheet.xml.match(new RegExp('saved-'+i,'g'))||[]).length,0),1);
  assert.match(result.workbook,/name="Evidências 2"/);assert.match(result.workbook,/name="Evidências 3"/);
  for(const sheet of result.sheets){assert.match(sheet.xml,/state="frozen"/);assert.match(sheet.xml,new RegExp('autoFilter ref="A1:C'+sheet.rows+'"'));}
  assert.ok(BULK_WORKSHEET_HYPERLINK_LIMIT<65530);
});
test('the row limit still rotates sheets even when records have no URLs',async()=>{
  const result=await fixture({rowLimit:3,records:Array.from({length:5},(_,i)=>({indicator:'qa-'+i,link:'sem referência',payload:'saved-'+i}))});
  assert.deepEqual(result.sheets.map(sheet=>sheet.rows),[3,3,2]);
  assert.deepEqual(result.sheets.map(sheet=>sheet.links),[0,0,0]);
});
