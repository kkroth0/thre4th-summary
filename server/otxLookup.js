import {isIP} from 'node:net';

export function otxIndicatorUrl(type, query) {
  const section=type==='ip'?(isIP(query)===6?'IPv6':isIP(query)===4?'IPv4':null):({domain:'domain',hash:'file',url:'url'})[type];
  if(!section)throw Object.assign(Error('Unsupported OTX indicator'),{response:{status:400}});
  return `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(query)}/general`;
}
