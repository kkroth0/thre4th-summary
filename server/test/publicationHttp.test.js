import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicationRequest, resolvePublicationHost } from '../publicationHttp.js';

test('an already-cancelled DNS request cannot start a resolver', async () => {
  const controller=new AbortController();controller.abort(Error('expired before DNS'));
  await assert.rejects(resolvePublicationHost('lab.example',{signal:controller.signal,createResolver:()=>{throw Error('must not run');}}),/expired before DNS/);
});

test('publication deadline includes a DNS lookup that never settles and performs no HTTP', async () => {
  let called=false;
  const request=createPublicationRequest({timeoutMs:15,lookup:()=>new Promise(()=>{}),http:{get:async()=>{called=true;}}});
  await assert.rejects(request('https://lab.example/report'),{code:'ETIMEDOUT'});
  assert.equal(called,false);
});

test('one deadline cancels DNS on a redirect after an earlier successful HTTP response', async () => {
  let signal;
  const request=createPublicationRequest({timeoutMs:15,
    lookup:async(host,options)=>{signal=options.signal;return host==='lab.example'?[{address:'1.1.1.1',family:4}]:new Promise(()=>{});},
    http:{get:async()=>({status:302,headers:{location:'https://next.example/report'}})},
  });
  await assert.rejects(request('https://lab.example/report'),{code:'ETIMEDOUT'});
  assert.equal(signal.aborted,true);
});

test('stalled HTTP shares the deadline; public literals bypass DNS and private/mixed destinations stay blocked', async () => {
  const stalled=createPublicationRequest({timeoutMs:15,http:{get:()=>new Promise(()=>{})}});
  await assert.rejects(stalled('https://1.1.1.1/report'),{code:'ETIMEDOUT'});
  let called=false;
  const http={get:async()=>{called=true;return{status:200};}};
  await assert.rejects(createPublicationRequest({http})('https://127.0.0.1/report'),/Non-public/);
  await assert.rejects(createPublicationRequest({http,lookup:async()=>[{address:'1.1.1.1',family:4},{address:'::1',family:6}]})('https://mixed.example'),/Non-public/);
  assert.equal(called,false);
});

test('independent DNS resolvers cancel both families without affecting another source', async () => {
  const controller=new AbortController();let cancelled=0;
  const pending=resolvePublicationHost('slow.example',{signal:controller.signal,createResolver:()=>({
    resolve4:()=>new Promise(()=>{}),resolve6:()=>new Promise(()=>{}),cancel:()=>{cancelled++;},
  })});
  const success=await resolvePublicationHost('fast.example',{signal:new AbortController().signal,createResolver:()=>({
    resolve4:async()=>['1.1.1.1'],resolve6:async()=>{throw Error('ENODATA');},cancel:()=>{},
  })});
  assert.deepEqual(success,[{address:'1.1.1.1',family:4}]);
  controller.abort(Error('cancelled lookup'));await assert.rejects(pending,/cancelled lookup/);
  assert.ok(cancelled>=1);
});

test('a pinned public response preserves headers and redirect validation does not reuse an earlier host address', async () => {
  const visited=[];
  const request=createPublicationRequest({lookup:async host=>[{address:host==='lab.example'?'1.1.1.1':'9.9.9.9',family:4}],http:{get:async(url,options)=>{
    const host=new URL(url).hostname;
    await new Promise((resolve,reject)=>options.lookup(host,{all:true},(error,records)=>{if(error)reject(error);else{visited.push(records[0].address);resolve();}}));
    assert.equal(options.headers['If-None-Match'],'etag'); assert.equal(options.proxy,false); assert.equal(options.maxContentLength,40000);
    return host==='lab.example'?{status:302,headers:{location:'https://next.example/report'}}:{status:304,headers:{etag:'etag'}};
  }}});
  const result=await request('https://lab.example/report',{headers:{'If-None-Match':'etag'},maxContentLength:40000});
  assert.deepEqual(visited,['1.1.1.1','9.9.9.9']); assert.equal(result.status,304); assert.equal(result.url,'https://next.example/report');
});
