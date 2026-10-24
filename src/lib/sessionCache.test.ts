import test from 'node:test';
import assert from 'node:assert/strict';
import { QueryClient } from '@tanstack/react-query';
import { resetSessionCache } from './sessionCache';

test('logout clears cached private evidence and cancels outstanding account reads',async()=>{
  const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
  client.setQueryData(['telegram-settings'],{username:'private-bot'});
  client.setQueryData(['actor-detail','private-actor'],{name:'Private actor'});
  let aborted=false,started!:()=>void;
  const ready=new Promise<void>(resolve=>{started=resolve;});
  const pending=client.fetchQuery({queryKey:['private-request'],queryFn:({signal})=>new Promise((_,reject)=>{
    signal.addEventListener('abort',()=>{aborted=true;reject(Error('cancelled'));},{once:true});started();
  })}).catch(()=>null);
  await ready;
  resetSessionCache(client,{authenticated:true,login:'alice',isPremium:true},{authenticated:false});
  await pending;
  assert.equal(aborted,true);assert.equal(client.getQueryCache().getAll().length,0);
});

test('switching accounts or losing premium clears previous results; refreshing the same identity keeps them',()=>{
  const client=new QueryClient();const alice={authenticated:true,login:'alice',isPremium:true};
  client.setQueryData(['evidence'],{value:'private'});
  resetSessionCache(client,alice,{...alice});assert.ok(client.getQueryData(['evidence']));
  resetSessionCache(client,alice,{...alice,login:'bob'});assert.equal(client.getQueryData(['evidence']),undefined);
  client.setQueryData(['evidence'],{value:'private'});
  resetSessionCache(client,alice,{...alice,isPremium:false});assert.equal(client.getQueryData(['evidence']),undefined);
  client.clear();
});
