import fs from 'node:fs';
import * as cheerio from 'cheerio';
import { parseFeed } from './feedParse.js';
import { canonicalArticleUrl } from './feedCollector.js';

export const PUBLICATION_SOURCES=JSON.parse(fs.readFileSync(new URL('./publicationSources.json',import.meta.url),'utf8'));
export const OT_PUBLICATION_SOURCES=[
  {domain:'cisa.gov',source:'CISA OT/ICS News',url:'https://www.cisa.gov/news-events/news?f%5B0%5D=article_topic%3A79',kind:'auto',listingOnly:true,includePath:'^/news-events/news/',layer:1,weight_boost:15,categories:['OT/ICS']},
  {domain:'claroty.com',source:'Claroty Team82 Research (BR)',url:'https://br.claroty.com/team82/research',kind:'auto',listingOnly:true,includePath:'^/team82/research/(?!white-papers/)',layer:3,weight_boost:15,categories:['OT/ICS']},
  {domain:'claroty.com',source:'Claroty Team82 White Papers (BR)',url:'https://br.claroty.com/team82/research?team82_resources_tab=team82_white_papers',kind:'auto',listingOnly:true,includePath:'^/team82/research/white-papers/',layer:3,weight_boost:15,categories:['OT/ICS']},
];
const clean=value=>String(value||'').replace(/\s+/g,' ').trim();
const host=value=>new URL(value).hostname.replace(/^www\./,'').toLowerCase();
const allowed=(address,source,{transport=false}={})=>{
  try {
    const url=new URL(address);
    if(!['https:','http:'].includes(url.protocol)||url.username||url.password||(url.port&&!['80','443'].includes(url.port))) return false;
    const domain=host(url), original=source.domain.replace(/^www\./,'');
    return domain===original || domain.endsWith('.'+original) || (original.endsWith('.medium.com')&&domain==='medium.com') || (transport&&['feeds.feedburner.com','feeds.feedblitz.com'].includes(domain));
  } catch { return false; }
};

export function discoverRss(html,address,source) {
  const $=cheerio.load(String(html||'')), candidates=[];
  $('link[rel~="alternate"][href]').each((_,element)=>{
    const node=$(element);
    if(!/rss|atom/i.test(node.attr('type')||'')||/comments|comentários/i.test(node.attr('title')||'')) return;
    const link=canonicalArticleUrl(node.attr('href'),address);
    if(link&&allowed(link,source,{transport:true})) candidates.push(link);
  });
  return [...new Set(candidates)].slice(0,3);
}

export function parsePublicationListing(html,address,source,now=new Date()) {
  const $=cheerio.load(String(html||'')), items=new Map();
  const put=({title,link,date,description=''})=>{
    const canonical=canonicalArticleUrl(link,address), text=clean(title);
    if(text.length<12||text.length>500||!canonical||!allowed(canonical,source)||canonicalArticleUrl(address)===canonical||/\/(?:tag|tags|category|categories|author|page|about|contact|pricing|products?|solutions?|login|signup)(?:\/|\?|$)/i.test(new URL(canonical).pathname)) return;
    if(source.includePath&&!new RegExp(source.includePath).test(new URL(canonical).pathname))return;
    const declared=new Date(date), valid=Number.isFinite(declared.getTime())&&declared.getTime()<=now.getTime()+86400000;
    if(!items.has(canonical))items.set(canonical,{title:text,link:canonical,source:source.source,layer:source.layer,weight_boost:source.weight_boost,pubDate:valid?declared.toISOString():now.toISOString(),dateInferred:!valid,description:clean(description).slice(0,300),text:clean(description).slice(0,20000)});
  };
  const visit=(value,depth=0)=>{
    if(!value||typeof value!=='object'||depth>12)return;
    if(Array.isArray(value)){value.slice(0,100).forEach(v=>visit(v,depth+1));return;}
    const types=Array.isArray(value['@type'])?value['@type']:[value['@type']];
    if(types.some(type=>/^(NewsArticle|BlogPosting|Article|Report)$/.test(type||'')))put({title:value.headline||value.name,link:value.url||value.mainEntityOfPage?.['@id'],date:value.datePublished,description:value.description});
    for(const key of ['@graph','itemListElement','item','mainEntity','blogPost'])visit(value[key],depth+1);
  };
  $('script[type="application/ld+json"]').each((_,el)=>{try{visit(JSON.parse($(el).text()));}catch{/* invalid metadata */}});
  $('script,style,noscript,nav,header,footer,aside,form').remove();
  $(source.includePath?'a[href]':'article h2 a[href],article h3 a[href],h2 a[href],h3 a[href],h4 a[href],a[href]:has(h2),a[href]:has(h3),a[href]:has(h4),.post-title a[href],.entry-title a[href]').each((_,element)=>{
    const node=$(element), link=node.attr('href');
    const card=node.closest('article,.post,.post-card,.article-card,.news-item,.blog-item,.post-item');
    const title=clean(node.find('h2,h3,h4').first().text())||clean(node.text());
    let pathname='';try{pathname=new URL(link,address).pathname;}catch{return;}
    if(!source.includePath&&!card.length&&!/(?:\/blog[s]?\/|\/news\/|\/research\/|\/posts?\/|\/\d{4}\/\d{2}\/|\/articles?\/)/i.test(pathname))return;
    put({title,link,date:card.find('time[datetime]').first().attr('datetime'),description:card.find('p').first().text()});
  });
  return [...items.values()].slice(0,60);
}

export function createPublicationResolver({request,now=()=>new Date()}={}) {
  return async(source,previous,{headers={}}={})=>{
    const readRss=async address=>{
      if(!allowed(address,source,{transport:true}))throw new Error('Feed outside publisher');
      const response=await request(address,{headers:previous?.discoveryUrl===address?headers:{}});
      if(response.status===304)return{response,items:[],metadata:{discoveryUrl:address,method:'rss'}};
      const items=parseFeed(response.data,source.source,source.layer,{feedUrl:response.url||address,now:now()}).filter(item=>allowed(item.link,source,{transport:true}));
      if(!items.length)throw new Error('RSS returned no publications');
      return{response,items,metadata:{discoveryUrl:address,method:'rss'}};
    };
    let lastError;
    if(previous?.method==='html'&&previous.discoveryUrl&&allowed(previous.discoveryUrl,source)) {
      try {
        const response=await request(previous.discoveryUrl,{headers});
        if(response.status===304)return{response,items:[],metadata:{discoveryUrl:previous.discoveryUrl,method:'html'}};
        const items=parsePublicationListing(response.data,response.url||previous.discoveryUrl,source,now());
        if(items.length)return{response,items,metadata:{discoveryUrl:previous.discoveryUrl,method:'html'}};
      } catch(error){lastError=error;}
    }
    const tried=new Set();
    for(const candidate of (source.listingOnly?[]:[previous?.method==='rss'?previous.discoveryUrl:null,...(source.rssCandidates||[])]).filter(Boolean)) {
      if(tried.has(candidate))continue;tried.add(candidate);
      try{return await readRss(candidate);}catch(error){lastError=error;}
    }
    let response;
    try { response=await request(source.url,{headers:previous?.method==='html'&&previous.discoveryUrl===source.url?headers:{}}); }
    catch(error) {
      const root=new URL('/',source.url).href;
      if(source.listingOnly||root===source.url||error.response?.status!==404)throw error;
      response=await request(root,{});
    }
    if(response.status===304)return{response,items:[],metadata:{discoveryUrl:source.url,method:'html'}};
    const page=response.url||source.url;
    for(const candidate of source.listingOnly?[]:discoverRss(response.data,page,source)) {
      if(tried.has(candidate))continue;tried.add(candidate);
      try{return await readRss(candidate);}catch(error){lastError=error;}
    }
    let items=parsePublicationListing(response.data,page,source,now());
    let listingResponse=response,listingUrl=source.url;
    if(!items.length){
      const $=cheerio.load(String(response.data||''));
      const link=$('a[href]').toArray().map(el=>({url:canonicalArticleUrl($(el).attr('href'),page),label:clean($(el).text())})).find(item=>item.url&&allowed(item.url,source)&&/^(?:blog|blogs|news|research|threat research|security research|publications|publicações)$/i.test(item.label)&&item.url!==canonicalArticleUrl(page));
      if(link){listingResponse=await request(link.url,{});listingUrl=link.url;items=parsePublicationListing(listingResponse.data,listingResponse.url||link.url,source,now());}
    }
    if(!items.length)throw lastError||new Error('No recognizable publications; source may require a dedicated adapter');
    return{response:listingResponse,items,metadata:{discoveryUrl:listingUrl,method:'html'}};
  };
}
