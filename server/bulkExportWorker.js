import {parentPort,workerData} from 'node:worker_threads';
import fsp from 'node:fs/promises';
import path from 'node:path';
import {createBulkStore} from './bulkJobs.js';
import {createBulkLocalSnapshot} from './bulkLocalSnapshot.js';
import {loadBulkEntityResolver} from './bulkEntityIdentity.js';
import {writeUnifiedBulkWorkbook} from './bulkUnifiedWorkbook.js';
import {eligibleSources,composeBulkRow} from './bulkShared.generated.mjs';
const {filePath,exportId,jobId,owner,outputDir,intelligencePath}=workerData;
const store=createBulkStore({filePath,readOnly:true,eligibleSources,composeRow:composeBulkRow});
let localSnapshot;
try{
 await fsp.mkdir(outputDir,{recursive:true});store.db.exec('BEGIN');
 const job=store.owned(owner,jobId),item=store.prepare('SELECT * FROM bulk_exports WHERE id=? AND owner=? AND job=?').get(exportId,owner,jobId);
 if(!item)throw Error('Exportação não encontrada.');const filters=JSON.parse(item.filters||'{}');
 if(filters.waitForComplete&&(job.state!=='complete'||store.prepare("SELECT COUNT(*) n FROM bulk_items WHERE job=? AND state NOT IN ('complete','unsupported')").get(jobId).n))throw Error('O Excel completo aguarda a conclusão de todas as consultas.');
 localSnapshot=createBulkLocalSnapshot({filePath:intelligencePath,spoolPath:path.join(outputDir,exportId+'.context'),owner});const entities=loadBulkEntityResolver();
 async function* rows(){for(const item of store.items(jobId,filters))yield entities.normalizeRow(localSnapshot.enrich(store.row(job,item)));}
 const result=await writeUnifiedBulkWorkbook({rows:rows(),outputPath:path.join(outputDir,exportId+'.xlsx'),progress:progress=>parentPort.postMessage({progress})});
 const local=localSnapshot.stats?.();store.db.exec('COMMIT');store.close();localSnapshot.close();
 result.summary={...result.summary,localChecked:local?.checked||0,axurMatches:local?.axurMatches||0,axurImportAt:local?.axurImportAt||null,generatedAt:local?.asOf||result.summary.generatedAt};
 parentPort.postMessage({done:true,...result,revision:job.revision});
}catch(error){try{store.close();}catch{}try{localSnapshot?.close();}catch{}parentPort.postMessage({error:error?.message||'Falha ao gerar a planilha.'});}
