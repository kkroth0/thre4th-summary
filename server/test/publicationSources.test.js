import test from 'node:test';
import assert from 'node:assert/strict';
import {PUBLICATION_SOURCES,OT_PUBLICATION_SOURCES,discoverRss,parsePublicationListing,createPublicationResolver} from '../publicationSources.js';
import {createPublicationRequest} from '../publicationHttp.js';
import {createFeedCollector} from '../feedCollector.js';
import {parseFeed} from '../feedParse.js';

const now=new Date('2026-10-13T12:00:00Z');
const source={domain:'news.example',source:'News',url:'https://news.example/',kind:'auto',rssCandidates:['https://news.example/feed/'],layer:2,weight_boost:10};
const rss='<rss><channel><item><title>Security vulnerability disclosed</title><link>https://news.example/blog/security-vulnerability</link><pubDate>Tue, 13 Oct 2026 10:00:00 GMT</pubDate><description>CVE-2026-12345 in gateway software</description></item></channel></rss>';

test('requested publishers are registered individually, including specific author/portal channels',()=>{
  assert.equal(PUBLICATION_SOURCES.length,165);
  assert.equal(new Set(PUBLICATION_SOURCES.map(row=>row.domain)).size,165);
  for(const domain of ['cybersecuritynews.com','cyberpress.org','medium.com','slowmist.medium.com','techcommunity.microsoft.com','blogs.cisco.com','securelist.ru','urlscan.io','team-cymru.com','blog.pulsedive.com'])assert.ok(PUBLICATION_SOURCES.some(row=>row.domain===domain));
  assert.ok(!PUBLICATION_SOURCES.some(row=>row.domain==='bleepingcomputer.com'));
  assert.ok(PUBLICATION_SOURCES.every(row=>row.kind==='auto'&&new URL(row.url).protocol==='https:'));
});

test('RSS discovery rejects cross-publisher URLs, credentials, local hosts and comment feeds',()=>{
  const html='<link rel="alternate" type="application/rss+xml" href="/rss.xml"><link rel="alternate" type="application/atom+xml" href="https://feeds.feedburner.com/news"><link rel="alternate" type="application/rss+xml" title="Comments" href="/comments/feed"><link rel="alternate" type="application/rss+xml" href="http://127.0.0.1/feed"><link rel="alternate" type="application/rss+xml" href="https://user:password@news.example/feed"><link rel="alternate" type="application/rss+xml" href="https://evil.example/feed">';
  assert.deepEqual(discoverRss(html,source.url,source),['https://news.example/rss.xml','https://feeds.feedburner.com/news']);
});

test('HTML extracts publication cards/JSON-LD, preserving real dates and excluding navigation/offsite links',()=>{
  const html='<nav><h2><a href="/blog/navigation">Navigation pretending to be a publication</a></h2></nav><script type="application/ld+json">{"@graph":[{"@type":"NewsArticle","headline":"Gateway security patch released","url":"https://news.example/blog/gateway-patch","datePublished":"2026-10-10T10:00:00Z","description":"CVE-2026-12345"}]}</script><article><h2><a href="/news/research-report">New threat research report</a></h2><time datetime="2026-10-12T09:00:00Z"></time><p>Malware infrastructure findings</p></article><article><h2><a href="https://evil.example/news/phishing">External phishing publication</a></h2></article><article><h2><a href="/pricing">Our enterprise pricing plan</a></h2></article><article><h2><a href="/blog/undated-report">Undated malware research report</a></h2></article>';
  const items=parsePublicationListing(html,source.url,source,now);
  assert.equal(items.length,3);
  assert.equal(items.find(row=>row.link.endsWith('gateway-patch')).pubDate,'2026-10-10T10:00:00.000Z');
  assert.equal(items.find(row=>row.link.endsWith('undated-report')).dateInferred,true);
  assert.equal(parsePublicationListing('<h1>Access denied</h1>',source.url,source,now).length,0);
});

test('automatic RSS joins the normal rolling collector, reuses validators, and retains data on failure',async()=>{
  const state=new Map(),health=[],calls=[];
  let phase=0;
  const request=async(address,{headers})=>{
    calls.push({address,headers});
    if(address===source.rssCandidates[0])throw new Error('404');
    if(address===source.url)return{status:200,url:address,data:'<link rel="alternate" type="application/rss+xml" href="/rss.xml">'};
    if(phase===1){assert.equal(headers['If-None-Match'],'"v1"');return{status:304};}
    if(phase===2)throw new Error('Source offline');
    return{status:200,data:rss,headers:{etag:'"v1"'}};
  };
  const collector=createFeedCollector({cache:{get:key=>state.get(key),set:(key,value)=>state.set(key,value)},parse:parseFeed,resolve:createPublicationResolver({request,now:()=>now}),now:()=>now,onHealth:(url,value)=>health.push(value)});
  const first=await collector.collect([source]);assert.equal(first.items.length,1);assert.equal(first.health.get(source.url).method,'rss');
  phase=1;const unchanged=await collector.collect([source]);assert.equal(unchanged.health.get(source.url).status,'unchanged');
  phase=2;const stale=await collector.collect([source]);assert.equal(stale.items.length,1);assert.equal(stale.health.get(source.url).status,'stale');
  assert.ok(health.some(row=>row.status==='collecting'));assert.ok(health.some(row=>row.ok));
});

test('HTML discovery caches the actual blog endpoint, rather than sending its validators to the home page',async()=>{
  const previous={method:'html',discoveryUrl:'https://news.example/blog/',items:[{}]};
  const requests=[];
  const resolver=createPublicationResolver({now:()=>now,request:async(url,options)=>{requests.push({url,...options});return{status:304};}});
  const result=await resolver(source,previous,{headers:{'If-None-Match':'"blog"'}});
  assert.equal(result.response.status,304);assert.equal(requests.length,1);assert.equal(requests[0].url,previous.discoveryUrl);assert.equal(requests[0].headers['If-None-Match'],'"blog"');
});

test('public HTTP pins DNS records and checks redirected destinations before contacting them',async()=>{
  const calls=[];
  const request=createPublicationRequest({lookup:async host=>[{address:host==='private.example'?'127.0.0.1':'1.1.1.1',family:4}],http:{get:async(address,options)=>{calls.push(address);assert.equal(options.maxRedirects,0);await new Promise((resolve,reject)=>options.lookup(new URL(address).hostname,{all:true},(error,records)=>{if(error)reject(error);else{assert.deepEqual(records,[{address:'1.1.1.1',family:4}]);resolve();}}));return{status:302,headers:{location:'http://private.example/metadata'}};}}});
  await assert.rejects(request('https://news.example/'),/Non-public/);assert.equal(calls.length,1);
  await assert.rejects(request('https://user:secret@news.example/'),/Unsafe/);
  await assert.rejects(request('http://news.example:8080/'),/Unsafe/);
});

test('Team82 research and white-paper channels keep separate scopes and carry OT provenance',()=>{
  const html='<main><a href="https://claroty.com/team82/research/plc-security-report">Industrial controller research report</a><a href="https://claroty.com/team82/research/white-papers/protocol-security">Industrial protocol security white paper</a><a href="https://claroty.com/company/product-overview">Claroty platform product overview</a></main>';
  const research=OT_PUBLICATION_SOURCES.find(row=>row.source==='Claroty Team82 Research (BR)'),papers=OT_PUBLICATION_SOURCES.find(row=>row.source==='Claroty Team82 White Papers (BR)');
  assert.equal(parsePublicationListing(html,research.url,research,now).length,1);
  assert.equal(parsePublicationListing(html,papers.url,papers,now).length,1);
  assert.ok(OT_PUBLICATION_SOURCES.every(row=>row.categories.includes('OT/ICS')));
});

test('a missing blog route falls back to advertised RSS on the publisher homepage',async()=>{
  const channel={...source,url:'https://news.example/blog',rssCandidates:[]};
  const resolver=createPublicationResolver({now:()=>now,request:async url=>{
    if(url===channel.url)throw Object.assign(new Error('404'),{response:{status:404}});
    if(url===source.url)return{status:200,url,data:'<link rel="alternate" type="application/rss+xml" href="/rss.xml">'};
    return{status:200,data:rss};
  }});
  const result=await resolver(channel,null);
  assert.equal(result.metadata.method,'rss');assert.equal(result.items.length,1);
});
