import { normalizeIndicator } from './iocIntelligence.js';
import { extractIOCs } from './ctiIntel.js';

// Narrative synthesis may omit IOC rows. The evidence appendix is a union of
// deterministic source extraction and the generated rows, with no slide cap.
export function completeReportEvidence(report,job,{items=[]}={}) {
  const urls=new Set(job.urls||[job.url]);
  const sources=items.filter(row=>urls.has(row.link));
  const values=sources.flatMap(row=>Object.values(row.iocs||{}).flat());
  for(const document of job.documents||[])values.push(...Object.values(extractIOCs(document.iocText||'',{plaintext:true})).flat());
  const iocs=Array.isArray(report.iocs)?[...report.iocs]:[];
  const known=new Set(iocs.map(row=>normalizeIndicator(row.valor)?.value).filter(Boolean));
  for(const value of values){const parsed=normalizeIndicator(value);if(!parsed||known.has(parsed.value))continue;known.add(parsed.value);
    iocs.push({categoria:parsed.type==='hash'?'Arquivo':'Rede',tipo:parsed.type==='hash'?({32:'MD5',40:'SHA1',64:'SHA256'}[parsed.value.length]):parsed.type==='ip'?'IP':parsed.type==='domain'?'Domínio':'URL',valor:parsed.value});
  }
  return {...report,iocs};
}
