import net from 'node:net';
import { isPublicIPv4, isPublicIPv6 } from './iocValidation.js';
const refang = value => String(value || '').trim().replace(/^hxxp/i,'http').replace(/\[\.\]|\(\.\)|\{\.\}/g,'.').replace(/\[:\]/g,':');
const validHost = domain => domain.length<=253 && domain.includes('.') && !/\.(?:localhost|local|internal|arpa|invalid|test)$/i.test(domain)
  && domain.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) && /^[a-z][a-z0-9-]+$/i.test(domain.split('.').at(-1));
export function normalizeIndicator(value, hint) {
  let text=refang(value);
  if (text.length>2048 || /[\u0000-\u0020]/.test(text)) return null;
  if (hint==='ip:port') text=text.replace(/^\[([^\]]+)\]:\d+$/,'$1').replace(/^(\d+\.\d+\.\d+\.\d+):\d+$/,'$1');
  const family=net.isIP(text);
  if(family) {
    if(family===4&&!isPublicIPv4(text))return null;
    if(family===6){if(!isPublicIPv6(text))return null;text=new URL(`http://[${text}]/`).hostname.slice(1,-1);}
    return {type:'ip',value:text.toLowerCase()};
  }
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(text)) return {type:'hash',value:text.toLowerCase()};
  try {
    if (/^https?:\/\//i.test(text)) {const url=new URL(text),host=url.hostname.replace(/^\[|\]$/g,'').replace(/\.$/,'');if(url.username||url.password||(net.isIP(host)?!normalizeIndicator(host):!validHost(host)))return null;url.hash='';if(!net.isIP(host))url.hostname=host;return {type:'url',value:url.href};}
    if(/[/:?#@]/.test(text))return null;
    const domain=new URL('https://'+text).hostname.toLowerCase().replace(/\.$/,'');
    if(!validHost(domain))return null;
    return {type:'domain',value:domain};
  }catch{return null;}
}
