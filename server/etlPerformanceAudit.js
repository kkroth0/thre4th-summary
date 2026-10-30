// Restore compact-summary verdict labels from the workbook's own analytical rows.
// All other ZIP parts, provider payloads and source states remain unchanged.
import fs from 'node:fs';import fsp from 'node:fs/promises';import path from 'node:path';import {createRequire} from 'node:module';import {pipeline} from 'node:stream/promises';import {StringDecoder} from 'node:string_decoder';import {pathToFileURL} from 'node:url';
const decode=s=>s.replace(/&#x([0-9a-f]+);|&#([0-9]+);|&(amp|lt|gt|quot|apos);/gi,(_,hex,num,name)=>hex?String.fromCodePoint(parseInt(hex,16)):num?String.fromCodePoint(Number(num)):({amp:'&',lt:'<',gt:'>',quot:'"',apos:"'"})[name.toLowerCase()]);
const escape=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const cells=xml=>new Map([...xml.matchAll(/<c\b[^>]*\br="([^"]+)"[^>]*(?<!\/)>([\s\S]*?)<\/c>/g)].map(match=>{const text=[...match[2].matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)].map(item=>decode(item[1])).join('');return[match[1],text||decode(match[2].match(/<v>([\s\S]*?)<\/v>/)?.[1]||'')];}));
const col=index=>{let s='';for(let n=index+1;n;n=Math.floor((n-1)/26))s=String.fromCharCode(65+(n-1)%26)+s;return s;};
async function review(source,destination,serverDir){
 const require=createRequire(path.join(serverDir,'package.json')),unzipper=require('unzipper'),JSZip=require('jszip'),shared=await import(pathToFileURL(path.join(serverDir,'bulkShared.generated.mjs')));
 const archive=await unzipper.Open.file(source),workbook=(await archive.files.find(file=>file.path==='xl/workbook.xml').buffer()).toString(),sheetId=name=>{const match=[...workbook.matchAll(/<sheet\b[^>]*\/>/g)].find(item=>item[0].includes('name="'+name+'"'));if(!match)throw Error('Required worksheet is missing');return match[0].match(/\bsheetId="(\d+)"/)[1];};
 const summaryPath='xl/worksheets/sheet'+sheetId('Resumo executivo')+'.xml',detailPath='xl/worksheets/sheet'+sheetId('Indicadores')+'.xml',summary=(await archive.files.find(file=>file.path===summaryPath).buffer()).toString(),summaryCells=cells(summary),targets=new Map();
 for(let row=39;row<=48;row++)if(summaryCells.get('M'+row)?.startsWith('undefined · ')){const query=summaryCells.get('B'+row);if(!query)throw Error('Executive query is missing');targets.set(query,row);}
 if(!targets.size)return{corrected:0,bytes:(await fsp.stat(source)).size};
 const queryColumn=col(shared.ANALYTICAL_COLUMNS.findIndex(item=>item[0]==='indicator')),verdictColumn=col(shared.ANALYTICAL_COLUMNS.findIndex(item=>item[0]==='verdict')),verdicts=new Map(),decoder=new StringDecoder('utf8');let carry='';
 const stream=archive.files.find(file=>file.path===detailPath).stream();
 for await(const chunk of stream){if(verdicts.size===targets.size)continue;carry+=decoder.write(chunk);let match,end=0;const rows=/<row\b[^>]*\br="(\d+)"[^>]*>[\s\S]*?<\/row>/g;
  while((match=rows.exec(carry))){end=rows.lastIndex;const row=Number(match[1]);if(row<=4)continue;const values=cells(match[0]),query=values.get(queryColumn+row);if(targets.has(query)){const verdict=values.get(verdictColumn+row);if(!verdict||verdict==='undefined')throw Error('Analytical verdict is missing');verdicts.set(targets.get(query),verdict);}}
  carry=carry.slice(end);if(carry.length>16*1024*1024)throw Error('Unexpected worksheet row size');
 }
 if(verdicts.size!==targets.size)throw Error('Executive indicators are absent from the analytical sheet');
 let corrected=0;const updated=summary.replace(/<c\b[^>]*\br="M(39|4[0-8])"[^>]*(?<!\/)>[\s\S]*?<\/c>/g,(cell,row)=>{const verdict=verdicts.get(Number(row));if(!verdict)return cell;const next=cell.replace(/(<(?:t|v)(?:\s[^>]*)?>)undefined( · )/,(_,prefix,suffix)=>prefix+escape(verdict)+suffix);if(next===cell)throw Error('Unexpected executive cell format');corrected++;return next;});
 if(corrected!==targets.size)throw Error('Executive correction count does not match');
 const zip=await JSZip.loadAsync(await fsp.readFile(source));zip.file(summaryPath,updated);await pipeline(zip.generateNodeStream({type:'nodebuffer',streamFiles:true,compression:'DEFLATE'}),fs.createWriteStream(destination,{mode:0o600}));
 const checked=await unzipper.Open.file(destination),checkedSummary=(await checked.files.find(file=>file.path===summaryPath).buffer()).toString();
 for(const row of verdicts.keys())if(cells(checkedSummary).get('M'+row)?.startsWith('undefined · '))throw Error('Executive label validation failed');
 const before=archive.files.filter(file=>!file.path.endsWith('/')).map(file=>file.path).sort(),after=checked.files.filter(file=>!file.path.endsWith('/')).map(file=>file.path).sort();if(JSON.stringify(before)!==JSON.stringify(after))throw Error('Workbook ZIP parts changed unexpectedly');
 const changedFiles=new Map(checked.files.map(file=>[file.path,file]));let unchangedParts=0;
 for(const file of archive.files){if(file.path===summaryPath||file.path.endsWith('/'))continue;const checkedFile=changedFiles.get(file.path);if(!Number.isFinite(file.crc32)||file.crc32!==checkedFile.crc32||file.uncompressedSize!==checkedFile.uncompressedSize)throw Error('A workbook data part changed unexpectedly');unchangedParts++;}
 return{corrected,bytes:(await fsp.stat(destination)).size,charts:checked.files.filter(file=>/\/charts\/chart\d+\.xml$/.test(file.path)).length,unchangedParts};
}
if(process.argv[2]==='--qa')console.log(await review(path.resolve(process.argv[4]),path.resolve(process.argv[5]),path.resolve(process.argv[3])));
else{
 const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
 const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
 const require=createRequire(path.join(root,'server/package.json')),env=require('dotenv').parse(fs.readFileSync(path.join(root,'.env'))),Database=require('better-sqlite3'),db=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'));db.pragma('busy_timeout=3000');
 const id='d283dbb8-fe6b-4d96-886b-fd6641276f2f',item=db.prepare('SELECT * FROM bulk_exports WHERE id=? AND owner=?').get(id,owner);if(item?.state!=='complete')throw Error('Requested workbook is not complete');
 const folder=path.resolve(env.BULK_EXPORTS_PATH||path.join(root,'server/.bulk-exports')),source=path.join(folder,id+'.xlsx'),destination=path.join(folder,id+'.quality.tmp.xlsx'),backup=path.join(folder,id+'.before-summary-review.xlsx');
 const originalMode=(await fsp.stat(fs.existsSync(backup)?backup:source)).mode&0o777;
 const result=await review(source,destination,path.join(root,'server'));if(result.corrected){await fsp.chmod(destination,originalMode);if(!fs.existsSync(backup))await fsp.link(source,backup);await fsp.rename(destination,source);const summary={...JSON.parse(item.summary||'{}'),bytes:result.bytes,executiveSummaryReviewedAt:new Date().toISOString()};db.prepare('UPDATE bulk_exports SET summary=?,updated=? WHERE id=? AND owner=?').run(JSON.stringify(summary),Date.now(),id,owner);}else await fsp.chmod(source,originalMode);
 db.close();console.log(JSON.stringify({readOnly:false,sourceDataUnchanged:true,presentationOnly:true,exportId:id,...result}));
}
