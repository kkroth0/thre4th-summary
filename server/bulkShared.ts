// Browser and durable jobs use the same compatibility, verdict and workbook rules.
import { formatVendorData, getVendorLink, extractVendorTimestamps, scoreThreatResults, resolveVendorsForQuery } from '../src/services/threatApi';
import type { BulkRow } from '../src/utils/bulkEnrichment';
export { prepareBulkInput } from '../src/utils/bulkEnrichment';
export { analyzeBulkRow, aggregateBulkAnalyses, PRIORITIES } from '../src/utils/bulkAnalysis';
export { addBulkDashboard } from '../src/utils/bulkDashboard';
export { ANALYTICAL_COLUMNS, ANALYTICAL_GROUPS } from '../src/utils/bulkAnalyticalSheets';
export { addBulkExcelCharts, prepareBulkChartZip } from '../src/utils/bulkExcelCharts';
export { BULK_COLORS } from '../src/utils/bulkDashboard';
export const BULK_SOURCES=['VirusTotal','AbuseIPDB','AlienVault OTX','ThreatFox','URLhaus','MalwareBazaar'];
export const eligibleSources=(query:string,sources:string[])=>resolveVendorsForQuery(query,sources).filter(x=>BULK_SOURCES.includes(x));
export function normalizeBulkVendor(query:string,name:string,body:any,status=200){
  if(status===404&&name==='VirusTotal')return{name,data:{Status:'No data'},link:getVendorLink(name,query),rawPayload:{...body,httpStatus:404,queryStatus:'not_found'},timeline:[]};
  return{name,data:formatVendorData(name,body,query),link:getVendorLink(name,query),timeline:extractVendorTimestamps(name,body),rawPayload:body,quota:body?.quota};
}
export function composeBulkRow(query:string,sources:any[],context:any,state:string,completedAt?:string):BulkRow{
  return {query,result:{...scoreThreatResults(query,sources.filter(v=>!v.isLoading)),vendorData:sources,totalVendors:sources.length},context,state:state as BulkRow['state'],completedAt};
}

export { valueText } from '../src/utils/iocExcelWorkbook';
export { scrubXml, workbookMetadata } from '../src/utils/deckTemplate';
