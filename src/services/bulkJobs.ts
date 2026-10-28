import type { BulkRow } from '@/utils/bulkEnrichment';
export const BULK_JOB_SOURCES=['VirusTotal','AbuseIPDB','AlienVault OTX','ThreatFox','URLhaus','MalwareBazaar','Axur'];
export interface BulkExport {id:string;state:string;created:number;updated:number;error?:string;revision:number;summary?:{total:number;localChecked:number;axurMatches:number;evidence:number;partial:number;charts:number;generatedAt:string}}
export interface BulkJob {id:string;state:string;total:number;processed:number;completed:number;partial:number;failed:number;pending:number;sources:string[];sourceCounts:{provider:string;completed:number;errors:number;blocked:number;pending:number;total:number}[];excluded:Record<string,number>;createdAt:string;updatedAt:string;revision:number;retryAt:number|null;exports:BulkExport[]}
export interface BulkPage {rows:BulkRow[];total:number;page:number;size:number}
export async function bulkRequest<T>(url:string,options:RequestInit={}):Promise<T>{
 const response=await fetch(url,{credentials:'same-origin',...options,headers:{...(options.body?{'Content-Type':'application/json'}:{}),...options.headers}});
 if(!response.ok){const body=await response.json().catch(()=>null);throw Error(body?.error||'Não foi possível atualizar o lote.');}return response.json();
}
export const bulkJobUrl=(id:string)=>'/api/bulk/jobs/'+encodeURIComponent(id);
