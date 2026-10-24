import JSZip from 'jszip';
import type {WeeklyCve} from '@/types/weekly-report';
import {A,P,R,first,parse,relation} from './weeklyPptxXml';

export function weeklyProductLogo(row:WeeklyCve):string|null{
 // An ecosystem label must not override an explicitly identified dependency.
 if(row.product&&((row.editorialFamily==='Node.js'&&!/^node[._ ]?js$/i.test(row.product))||(row.editorialFamily==='PHP'&&!/^php$/i.test(row.product))||(row.editorialFamily==='Java'&&!/java|jdk|jre|graal/i.test(row.product))))return null;
 if(row.editorialFamily==='Java')return 'java';if(row.editorialFamily==='PHP')return 'php';if(row.editorialFamily==='Node.js')return 'node';
 const product=`${row.vendor} ${row.product}`.toLowerCase();
 if(/\bsiemens\b/.test(product))return 'siemens';if(/\bplex\b/.test(product))return 'plex';if(/\bsiteguard\b/.test(product))return 'siteguard';return null;
}
// Marks identify only the actual product. Unknown vendors get no logo.
export async function fillWeeklyProductLogos(zip:JSZip,doc:XMLDocument,rels:XMLDocument,rows:WeeklyCve[]){
 const tree=first(doc,P,'spTree'),shapes=Array.from(doc.getElementsByTagNameNS(P,'sp'));
 for(const[rowIndex,row]of rows.slice(0,3).entries()){
  const key=weeklyProductLogo(row);if(!key)continue;
  const file=`ppt/media/weekly-brand-${key}.png`;
  if(!zip.file(file)){const response=await fetch(`/templates/weekly-logos/${key}.png`);if(!response.ok)throw Error('Logo indisponível: '+key);zip.file(file,await response.arrayBuffer());}
  const bytes=await zip.file(file)!.async('uint8array');if(bytes.length<24||bytes[0]!==137||bytes[1]!==80)throw Error('Logo inválida');
  const view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),w=view.getUint32(16),h=view.getUint32(20),ratio=Math.min(685800/w,310896/h),width=Math.round(w*ratio),height=Math.round(h*ratio);
  const title=shapes.find(shape=>Number(first(shape,P,'cNvPr')?.getAttribute('id'))===9+rowIndex);if(!title)continue;
  const off=first(title,A,'off'),ext=first(title,A,'ext'),oldX=Number(off.getAttribute('x')),right=oldX+Number(ext.getAttribute('cx'));off.setAttribute('x','1600200');ext.setAttribute('cx',String(right-1600200));
  const top=Number(off.getAttribute('y'))-100584,y=top+Math.round((512064-height)/2),x=777240+Math.round((685800-width)/2),rid='weeklyBrand'+rowIndex;
  const picture=parse(`<p:pic xmlns:p="${P}" xmlns:a="${A}" xmlns:r="${R}"><p:nvPicPr><p:cNvPr id="${12000+rowIndex}" name="Logo ${key}"/><p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr><p:nvPr/></p:nvPicPr><p:blipFill><a:blip r:embed="${rid}"/><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr><a:xfrm><a:off x="${x}" y="${y}"/><a:ext cx="${width}" cy="${height}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>`).documentElement;
  tree.appendChild(doc.importNode(picture,true));relation(rels,rid,'image',`../media/weekly-brand-${key}.png`);
 }
}
