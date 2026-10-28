import type ExcelJS from 'exceljs';
import { BULK_COLORS as C } from './bulkDashboard';
export type AnalyticalColumn=[string,string,number];
const status=(source:string):AnalyticalColumn=>['status:'+source,'Consulta',19];
export const ANALYTICAL_GROUPS:{title:string;columns:AnalyticalColumn[]}[]=[
  {title:'IDENTIFICAÇÃO E TRIAGEM',columns:[['rank','#',6],['priority','Prioridade',23],['indicator','Indicador',46],['type','Tipo',13],['verdict','Veredito das fontes',22],['score','Score original',14],['state','Processamento',18],['actors','Atores declarados pela fonte',30],['families','Famílias de malware',30],['basis','Base da relação',30],['notes','Leitura e ressalvas',65]]},
  {title:'AXUR / INTELIGÊNCIA CORRELACIONADA',columns:[['status:Axur','Consulta Axur (base / API)',25],['axLocalStatus','Consulta à base importada',36],['axImportAt','Última varredura Axur (ISO)',28],['localReadAt','Cruzamento local (ISO)',28],['axReports','Relatórios que citam o IOC',60],['axLinks','Referências dos relatórios',65],['axActors','Atores citados no relatório',38],['axMalware','Malware citado no relatório',38],['axCves','CVEs citadas',30],['axDates','Datas das publicações (ISO)',30]]},
  {title:'CONTEXTO E COMPORTAMENTO CITADO',columns:[['mentions','Atores mencionados no contexto',38],['techniques','Técnicas ATT&CK citadas',38],['tactics','Táticas mapeadas',38],['publications','Publicações relacionadas',18],['evidence','Evidências do histórico',18]]},
  {title:'VIRUSTOTAL',columns:[status('VirusTotal'),['vtStatus','Resultado',26],['vtDetections','Detecções',16],['vtMalicious','Motores maliciosos',18],['vtReputation','Reputação',16],['vtNames','Classificação de ameaça',36],['vtTags','Tags',38]]},
  {title:'ABUSEIPDB',columns:[status('AbuseIPDB'),['abScore','Confiança de abuso (%)',22],['abReports','Relatos',14],['abReporters','Relatores distintos',18],['abLast','Último relato (ISO)',28],['abUsage','Uso da rede',26],['abWhitelisted','Whitelist da fonte',20]]},
  {title:'ALIENVAULT OTX',columns:[status('AlienVault OTX'),['otxStatus','Resultado',26],['otxPulses','Pulses',14],['otxActors','Adversários informados (texto da fonte)',38],['otxFamilies','Malware informado nos pulses',36],['otxTags','Tags',38]]},
  {title:'THREATFOX',columns:[status('ThreatFox'),['tfStatus','Resultado',24],['tfMalware','Famílias de malware',32],['tfType','Tipo de ameaça',32],['tfConfidence','Confiança (%)',18],['tfMatches','Registros correspondentes',20],['tfFirst','Primeira observação',27],['tfLast','Última observação',27],['tfReference','Referência',65]]},
  {title:'URLHAUS',columns:[status('URLhaus'),['uhStatus','Resultado',26],['uhUrls','URLs registradas',18],['uhActive','URLs online informadas',22],['uhMalware','Malware / assinatura',32],['uhTags','Tags',38]]},
  {title:'MALWAREBAZAAR',columns:[status('MalwareBazaar'),['mbStatus','Resultado',24],['mbFile','Nome do arquivo',40],['mbType','Tipo de arquivo',18],['mbSignature','Assinatura',30],['mbTags','Tags',38],['mbFirst','Primeira observação',27]]},
  {title:'REVISÃO DE FALSO POSITIVO',columns:[status('abuse.ch Hunting'),['fpStatus','Revisão abuse.ch',60],['fpScope','Escopo da correspondência',26]]},
  {title:'INFRAESTRUTURA E REGISTRO',columns:[['country','País informado',17],['asn','ASN',22],['organization','Organização da rede',42],['isp','ISP',36],['prefix','Prefixo da rede',24],['rdns','Nome reverso (rDNS)',42],status('DNS / Team Cymru'),['registrar','Registrador',32],['created','Criação do domínio',28],status('WHOIS')]},
  {title:'COBERTURA E RASTREABILIDADE',columns:[['completedAt','Conclusão (ISO)',29],['sources','Fontes consultadas',48],['failedSources','Fontes indisponíveis',42],['sourceErrors','Erros e pendências',70]]},
];
export const ANALYTICAL_COLUMNS=ANALYTICAL_GROUPS.flatMap(g=>g.columns);
export function styleAnalyticalSheet(ws:ExcelJS.Worksheet){
  ws.spliceRows(1,0,[],[],[]);
  ws.mergeCells('A1:K1');ws.getCell('A1').value=`ThreatSumm4ry  /  ${ws.name}`;ws.getRow(1).height=34;
  ws.mergeCells('A2:K2');ws.getCell('A2').value='Atribuição declarada e menção de contexto são campos distintos. Campos vazios não significam resultado negativo. Filtre os registros na linha 4.';ws.getRow(2).height=38;
  for(const n of [1,2]){const c=ws.getCell(n,1);c.font={name:'Arial',size:n===1?17:10,bold:n===1,color:{argb:n===1?C.white:C.muted}};c.fill={type:'pattern',pattern:'solid',fgColor:{argb:n===1?C.ink:C.pale}};c.alignment={wrapText:true,vertical:'middle',indent:1};}
  let col=1;ANALYTICAL_GROUPS.forEach((g,i)=>{const end=col+g.columns.length-1;ws.mergeCells(3,col,3,end);const c=ws.getCell(3,col);c.value=g.title;c.font={name:'Arial',size:10,bold:true,color:{argb:i%2?C.white:C.ink}};c.fill={type:'pattern',pattern:'solid',fgColor:{argb:i%2?C.ink:C.yellow}};c.alignment={vertical:'middle',horizontal:'left',indent:1};col=end+1;});
  ws.getRow(3).height=28;ws.getRow(4).height=44;ws.views=[{state:'frozen',xSplit:4,ySplit:4,showGridLines:false,zoomScale:80}];
  ws.autoFilter={from:{row:4,column:1},to:{row:Math.max(4,ws.rowCount),column:ANALYTICAL_COLUMNS.length}};
  ws.pageSetup={orientation:'landscape',fitToPage:true,fitToWidth:1,fitToHeight:0,printTitlesRow:'1:4'};ws.properties.tabColor={argb:C.teal};
  ws.eachRow((row,n)=>{if(n<4)return;row.height=n===4?44:58;row.fill={type:'pattern',pattern:'solid',fgColor:{argb:n===4?C.ink:n%2?C.pale:C.white}};row.eachCell(cell=>{
    const key=String(ws.getColumn(cell.col).key||'');
    if(n>4&&['axLinks','tfReference'].includes(key)&&typeof cell.value==='string'&&/^https?:\/\/[^\s;]+$/.test(cell.value))cell.value={text:cell.value,hyperlink:cell.value};
    if(n>4&&key==='techniques'&&typeof cell.value==='string'&&/^T\d{4}(?:\.\d{3})?$/.test(cell.value)){const id=cell.value;cell.value={text:id,hyperlink:`https://attack.mitre.org/techniques/${id.replace('.','/')}/`};}
    const link=cell.value&&typeof cell.value==='object'&&'hyperlink'in cell.value;
    cell.font={name:'Arial',size:10,bold:n===4,color:{argb:n===4?C.white:link?'FF0563C1':C.ink},...(link?{underline:true}:{})};
    cell.alignment={vertical:n===4?'middle':'top',wrapText:true};cell.fill={type:'pattern',pattern:'solid',fgColor:{argb:n===4?C.ink:n%2?C.pale:C.white}};
    if(n>4&&key==='priority'){const color=cell.value==='Investigar'?'FFFFDDDD':cell.value==='Atenção'?'FFFFEDBC':cell.value==='Revisar'?'FFFFF6D9':'FFE7F0F4';cell.fill={type:'pattern',pattern:'solid',fgColor:{argb:color}};cell.font={name:'Arial',size:10,bold:true,color:{argb:C.ink}};}
    if(n>4&&key.startsWith('status:'))cell.font={name:'Arial',size:10,color:{argb:cell.value==='Indisponível'?C.red:cell.value==='Respondida'?C.teal:C.muted}};
  });});
}
