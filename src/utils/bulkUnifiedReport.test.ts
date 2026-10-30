import test from 'node:test';
import assert from 'node:assert/strict';
import type {BulkRow} from './bulkEnrichment';
import {createUnifiedBulkRegistry,projectUnifiedBulkRow,UNIFIED_INDICATOR_COLUMNS} from './bulkUnifiedReport';

function fixture():BulkRow {
 return {query:'93.184.216.34',state:'partial',context:{publications:[],errors:['Internal diagnostic'],entityResolutionVersion:'qa',entityResolutions:[
  {sourceKind:'actor',sourceLabel:'Evil Corp',sourceId:'G0119',kind:'actor',id:'G0119',name:'Indrik Spider',verification:'catalog',catalogSource:'attack'},
  {sourceKind:'actor',sourceLabel:'Cobalt Strike',sourceId:'',kind:'software',id:'S0154',name:'Cobalt Strike',verification:'catalog',catalogSource:'attack'},
  {sourceKind:'actor',sourceLabel:'Automated Scanner',sourceId:'',kind:'unclassified',id:'',name:'Automated Scanner',verification:'unresolved',catalogSource:''},
 ],evidence:[{provider:'OTX',title:'Campaign report',link:'https://otx.alienvault.com/pulse/qa',published:'2026-10-29T12:00:00Z',collectedAt:'2026-10-30T00:00:00Z',confidence:90,reputation:null,entities:[{kind:'actor',name:'Evil Corp',id:'G0119',relation:'mentioned-by-source'},{kind:'actor',name:'Cobalt Strike',id:'',relation:'mentioned-by-source'},{kind:'actor',name:'Automated Scanner',id:'',relation:'mentioned-by-source'}]}]},result:{query:'93.184.216.34',threatLevel:'suspicious',overallScore:70,detections:1,totalVendors:2,vendorData:[{name:'AlienVault OTX',data:{'Pulse Details':[{id:'qa',name:'Campaign report',adversary:'',malwareFamilies:[],attackIds:['T1059.001'],created:'2026-10-29T12:00:00Z'}]}},{name:'VirusTotal',data:{},error:'Quota exceeded',rawPayload:{secretDiagnostic:'not for Excel'}}]}};
}
test('unified mentions are deduplicated and catalog actors remain separate from software and unclassified labels',()=>{
 const input=fixture();input.context!.evidence.push({...input.context!.evidence[0]});
 const projection=projectUnifiedBulkRow(input);
 assert.equal(projection.record.mentions,1);assert.equal(projection.record.actors,'Indrik Spider');assert.equal(projection.record.actorIds,'G0119');assert.equal(projection.record.malware,'Cobalt Strike');
 assert.equal(projection.mentions[0].entities.length,2);assert.equal(projection.mentions[0].entities[0].association,'Menção em publicação');
 for(const word of ['VirusTotal','OTX','quota','pendente','Internal diagnostic','secretDiagnostic','Automated Scanner'])assert.ok(!String(projection.record.context).includes(word));
 assert.ok(!UNIFIED_INDICATOR_COLUMNS.some(([key])=>/source|status|state|error|raw|payload|coverage/i.test(key)));
});
test('one shared publication retains both indicator edges and normalized entity links without becoming multiple independent publications',()=>{
 const registry=createUnifiedBulkRegistry();const first=registry.add(projectUnifiedBulkRow(fixture()));const secondInput=fixture();secondInput.query='93.184.216.35';const second=registry.add(projectUnifiedBulkRow(secondInput));const report=registry.finish();
 assert.equal(report.publicationCount,1);assert.equal(report.mentions,2);assert.equal(report.publications[0].count,2);assert.equal(report.mentionedIndicators,2);
 assert.equal(first.mentions[0].publication,second.mentions[0].publication);assert.equal(first.relations[0].name,'Indrik Spider');assert.equal(first.relations[0].catalogId,'G0119');
 assert.deepEqual(report.analysis.actors,[{name:'Indrik Spider',count:2}]);assert.equal(report.techniques[0].actors,'Indrik Spider');
});
test('reputation lookups and failed providers never create fictitious publication mentions or clean verdicts',()=>{
 const input=fixture();input.result!.threatLevel='safe';input.result!.vendorData=[];input.context!.evidence=[{...input.context!.evidence[0],provider:'VirusTotal',link:'https://www.virustotal.com/gui/ip-address/93.184.216.34'}];
 const projection=projectUnifiedBulkRow(input);assert.equal(projection.record.mentions,0);assert.equal(projection.record.verdict,'Sem evidência suficiente');
});
test('generic attack categories are not malware families and absent ASN values never enter network rankings',()=>{
 const input=fixture();input.context!.entityResolutions!.push({sourceKind:'malware',sourceLabel:'SSH Brute-Force',sourceId:'',kind:'software',id:'',name:'SSH Brute-Force',verification:'source-reported',catalogSource:''});
 input.context!.evidence[0].entities.push({kind:'malware',name:'SSH Brute-Force',id:'',relation:'mentioned-by-source'});input.result!.vendorData.push({name:'DNS / Team Cymru',data:{ASN:'ASNone'}});
 const projection=projectUnifiedBulkRow(input);assert.ok(!String(projection.record.malware).includes('Brute-Force'));assert.equal(projection.record.asn,null);const registry=createUnifiedBulkRegistry();registry.add(projection);assert.deepEqual(registry.finish().analysis.asns,[]);
});
