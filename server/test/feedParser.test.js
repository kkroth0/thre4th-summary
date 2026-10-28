import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createFeedParser } from '../feedParser.js';
import { parseFeed } from '../feedParse.js';
import { createFeedCollector } from '../feedCollector.js';
const xml='<rss><channel><item><title>Security advisory</title><link>https://vendor.example/a</link><description>Report CVE-2026-12345</description><pubDate>Tue, 27 Oct 2026 12:00:00 GMT</pubDate></item></channel></rss>';
test('isolated parser preserves dates, text and evidence exactly',async t=>{
  const parse=createFeedParser();t.after(()=>parse.close());
  const args=[xml,'Vendor',1,{now:new Date('2026-10-27T13:00:00Z')}];
  assert.deepEqual(await parse(...args),parseFeed(...args));
  await assert.rejects(parse('invalid','Vendor',1));
  assert.equal((await parse(...args)).length,1);
});
test('worker failure rejects only that source and the next source can continue',async t=>{
  let workers=0;
  const parse=createFeedParser({makeWorker:()=>{
    const worker=new EventEmitter(); const index=workers++;
    worker.ref=()=>{};worker.unref=()=>{};worker.terminate=async()=>{};
    worker.postMessage=({id})=>queueMicrotask(()=>index===0?worker.emit('error',Error('memory limit')):worker.emit('message',{id,items:[]}));
    return worker;
  }});t.after(()=>parse.close());
  const results=await Promise.allSettled([parse(xml,'A',1),parse(xml,'B',1)]);
  assert.equal(results[0].status,'rejected');assert.equal(results[1].status,'fulfilled');assert.equal(workers,2);
});
test('an asynchronous parsing failure keeps the source previous snapshot',async()=>{
  const cached={items:[{title:'Previous',link:'https://vendor.example/a',pubDate:'2026-10-27T12:00:00Z'}]};
  const collector=createFeedCollector({request:async()=>({status:200,data:xml}),parse:async()=>{throw Error('Parser unavailable');},cache:{get:()=>cached,set:()=>assert.fail('failed parse must not overwrite cache')},now:()=>new Date('2026-10-27T13:00:00Z')});
  const result=await collector.collect([{url:'https://vendor.example/feed',source:'Vendor',layer:1}]);
  assert.equal(result.items[0].title,'Previous');assert.equal(result.items[0].collectionStatus,'stale');
});
