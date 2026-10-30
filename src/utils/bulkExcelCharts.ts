import JSZip from 'jszip';
import parts from './bulkChartParts.json';
import { analyzeBulkRows, type BulkAnalysis } from './bulkAnalysis';
import { bulkChartData } from './bulkDashboard';
import type { BulkRow } from './bulkEnrichment';

const xml=(s:string)=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');
const selectedCharts=[1,2,3,7];
/** Native editable charts authored with Artifact Tool, bound to the snapshot's helper cells. */
export async function prepareBulkChartZip(buffer:Uint8Array,rows:BulkRow[],snapshot?:BulkAnalysis){
  const zip=await JSZip.loadAsync(buffer),data=bulkChartData(snapshot||analyzeBulkRows(rows));
  for(const [name,source]of Object.entries(parts)){
    if(name==='contentTypes')continue;let value=source;
    const number=name.match(/\/charts\/chart(\d+)\.xml$/)?.[1];
    if(number&&!selectedCharts.includes(Number(number)))continue;
    if(name==='xl/drawings/drawing1.xml'){
      let position=0;
      value=value.replace(/<xdr:twoCellAnchor>[\s\S]*?<\/xdr:twoCellAnchor>/g,(anchor)=>{
        const index=Number(anchor.match(/<xdr:cNvPr id="(\d+)"/)?.[1]);
        if(!selectedCharts.includes(index))return '';
        const slot=position++,row=9+Math.floor(slot/2)*22,column=slot%2===0?1:13;
        let n=0,c=0;return anchor.replace(/<xdr:row>\d+<\/xdr:row>/g,()=>`<xdr:row>${n++===0?row:row+19}</xdr:row>`).replace(/<xdr:col>\d+<\/xdr:col>/g,()=>`<xdr:col>${c++===0?column:column+11}</xdr:col>`);
      });
    }
    if(name==='xl/drawings/_rels/drawing1.xml.rels')value=value.replace(/<Relationship\b[^>]*\/>/g,(relation)=>selectedCharts.includes(Number(relation.match(/chart(\d+)\.xml/)?.[1]))?relation:'');
    if(number){
      const i=Number(number)-1,items=data[i],start=3+i*14,end=start+Math.max(1,items.length)-1;
      if(i===0||i===1||i===2){let changed=false;value=value.replace(/<c:title>[\s\S]*?<\/c:title>/,title=>title.replace(/<a:t>[\s\S]*?<\/a:t>/,()=>{changed=true;return `<a:t>${i===0?'Atores relacionados nas publicações':i===1?'Malwares e ferramentas relacionados':'Técnicas ATT&amp;CK relacionadas'}</a:t>`;}));if(!changed)throw Error('Título do gráfico de entidades não encontrado.');}
      value=value.replace(/<c:cat>[\s\S]*?<\/c:cat>/,`<c:cat><c:strRef><c:f>'_dados'!$A$${start}:$A$${end}</c:f><c:strCache><c:ptCount val="${items.length}"/>${items.map((x,j)=>`<c:pt idx="${j}"><c:v>${xml(x.name)}</c:v></c:pt>`).join('')}</c:strCache></c:strRef></c:cat>`)
        .replace(/<c:val>[\s\S]*?<\/c:val>/,`<c:val><c:numRef><c:f>'_dados'!$B$${start}:$B$${end}</c:f><c:numCache><c:formatCode>0</c:formatCode><c:ptCount val="${items.length}"/>${items.map((x,j)=>`<c:pt idx="${j}"><c:v>${x.count}</c:v></c:pt>`).join('')}</c:numCache></c:numRef></c:val>`);
      // Horizontal rankings leave room for long actor/family names. Types stay vertical.
      if(i!==4&&i!==5)value=value.replace(/<c:barDir[^>]*\/>/,'<c:barDir val="bar"/>').replace(/(<c:catAx>[\s\S]*?<c:axPos) val="b"/,'$1 val="l"').replace(/(<c:valAx>[\s\S]*?<c:axPos) val="l"/,'$1 val="b"');
      if(i!==4){
        const max=Math.max(1,...items.map(x=>x.count)),step=Math.max(1,Math.ceil(max/5)),upper=Math.ceil(max/step)*step;
        value=value.replace(/<c:legend>[\s\S]*?<\/c:legend>/,'').replace(/<c:gapWidth[^>]*\/>/,'<c:gapWidth val="65"/>');
        if(!value.includes('<c:gapWidth'))value=value.replace(/(<c:barChart>[\s\S]*?)(<c:axId)/,'$1<c:gapWidth val="65"/>$2');
        value=value.replace(/(<c:valAx>[\s\S]*?<c:scaling>)([\s\S]*?)(<\/c:scaling>)/,(_m,p,c,s)=>`${p}${c}<c:max val="${upper}"/><c:min val="0"/>${s}`)
          .replace('</c:valAx>',`<c:majorUnit val="${step}"/></c:valAx>`);
        if(i!==5)value=value.replace(/(<c:catAx>[\s\S]*?<c:orientation) val="minMax"/,'$1 val="maxMin"');
        if(!items.length)value=value.replace(/<c:delete val="0"\s*\/>/g,'<c:delete val="1"/>');
        value=value.replace(/E5C900/g,['087F8C','F1BC32','527AA3','8570A4','','087F8C','527AA3','F1BC32'][i]);
      }
      value=value.replace(/<c:plotVisOnly[^>]*\/>/,'<c:plotVisOnly val="0"/>');
    }
    if(zip.file(name))throw Error('Conflito ao incluir gráficos do enriquecimento.');zip.file(name,value);
  }
  const types=await zip.file('[Content_Types].xml')!.async('string');
  const overrides=parts.contentTypes.match(/<Override\b[^>]*\/>/g)?.filter(s=>/PartName="\/xl\/drawings\//.test(s)&&(!/chart\d+\.xml/.test(s)||selectedCharts.includes(Number(s.match(/chart(\d+)\.xml/)?.[1]))))||[];
  zip.file('[Content_Types].xml',types.replace('</Types>',overrides.join('')+'</Types>'));
  let sheet=await zip.file('xl/worksheets/sheet1.xml')!.async('string');
  if(!sheet.includes('xmlns:r='))sheet=sheet.replace('<worksheet ','<worksheet xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ');
  zip.file('xl/worksheets/sheet1.xml',sheet.replace('</worksheet>','<drawing r:id="rIdBulkCharts"/></worksheet>'));
  const path='xl/worksheets/_rels/sheet1.xml.rels';
  let rels=zip.file(path)?await zip.file(path)!.async('string'):'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>';
  rels=rels.replace(/<Relationships([^>]*)\/>/,'<Relationships$1></Relationships>');
  zip.file(path,rels.replace('</Relationships>','<Relationship Id="rIdBulkCharts" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing1.xml"/></Relationships>'));
  return zip;
}
export async function addBulkExcelCharts(buffer:Uint8Array,rows:BulkRow[],snapshot?:BulkAnalysis){
  return (await prepareBulkChartZip(buffer,rows,snapshot)).generateAsync({type:'uint8array',compression:'DEFLATE'});
}
