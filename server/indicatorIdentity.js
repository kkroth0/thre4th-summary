import net from 'node:net';
const refang = value => String(value || '').trim().replace(/^hxxp/i,'http').replace(/\[\.\]|\(\.\)|\{\.\}/g,'.').replace(/\[:\]/g,':');
export function normalizeIndicator(value, hint) {
  let text=refang(value);
  if (text.length>2048 || /[\u0000-\u0020]/.test(text)) return null;
  if (hint==='ip:port') text=text.replace(/^\[([^\]]+)\]:\d+$/,'$1').replace(/^(\d+\.\d+\.\d+\.\d+):\d+$/,'$1');
  const family=net.isIP(text);
  if(family) {
    if(family===4){const [a,b]=text.split('.').map(Number);if(a===0||a===10||a===127||a>=224||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===169&&b===254)||(a===100&&b>=64&&b<=127))return null;}
    if(family===6){text=new URL(`http://[${text}]/`).hostname.slice(1,-1);if(/^(::|f[cd]|fe[89ab]|ff|2001:db8)/i.test(text))return null;}
    return {type:'ip',value:text.toLowerCase()};
  }
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(text)) return {type:'hash',value:text.toLowerCase()};
  try {
    if (/^https?:\/\//i.test(text)) {const url=new URL(text),host=url.hostname.replace(/^\[|\]$/g,'');if(url.username||url.password||(net.isIP(host)?!normalizeIndicator(host):!host.includes('.')||/\.(?:localhost|local|internal|invalid|test)$/i.test(host)))return null;url.hash='';return {type:'url',value:url.href};}
    if(/[/:?#@]/.test(text))return null;
    const domain=new URL('https://'+text).hostname.toLowerCase();
    if(!domain.includes('.')||/\.(?:localhost|local|internal|arpa|invalid|test)$/i.test(domain)||! /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/i.test(domain))return null;
    return {type:'domain',value:domain};
  }catch{return null;}
}
