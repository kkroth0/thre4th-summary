import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { proposeWatchTerms, createWatchSuggestions } from '../watchSuggestions.js';

const now = new Date('2026-10-15T12:00:00Z');
const profile = {ownerId:'one',id:'p1',name:'Bank',brands:[],sectors:['Financial']};
const report = (link, storyId='event') => ({link:`https://research.example/${link}`,title:'Phishing campaign uses fake Adobe login pages',description:'Attackers target banks and steal credentials.',pubDate:'2026-10-10T12:00:00Z',storyId});

test('proposals count distinct events, cite context and never mutate monitored brands', () => {
  const proposals = proposeWatchTerms([report('one'),report('two'),report('three','other'),{...report('future'),pubDate:'2027-01-01'}],profile,{now});
  assert.equal(proposals.length,1); assert.equal(proposals[0].term,'adobe'); assert.equal(proposals[0].events,2); assert.equal(proposals[0].sources,1);
  assert.equal(proposals[0].publications.length,3); assert.deepEqual(profile.brands,[]);
  assert.equal(proposeWatchTerms([report('one')],{...profile,brands:['adobe']},{now}).length,0);
  assert.equal(proposeWatchTerms([report('one')],{...profile,sectors:['Energy']},{now}).length,0);
});

test('acceptance requires owner, preserves decisions and only updates an explicit reviewed term', () => {
  const db = new Database(':memory:'), store = createWatchSuggestions(db), proposals = proposeWatchTerms([report('one')],profile,{now});
  assert.equal(store.list(profile,proposals).length,1);
  let updated;
  const profiles = {update:(owner,id,input)=>{updated={owner,id,...input};}};
  assert.throws(()=>store.review('two',profile,proposals[0].id,'accepted',profiles),/encontrada/);
  store.review('one',profile,proposals[0].id,'accepted',profiles); assert.deepEqual(updated.brands,['adobe']);
  assert.equal(store.list(profile,proposals).length,0);
  assert.equal(store.list({...profile,ownerId:'two'},proposeWatchTerms([report('one')],{...profile,ownerId:'two'},{now})).length,1);
  store.dropProfile('one','p1'); assert.equal(db.prepare("SELECT COUNT(*) n FROM watch_term_suggestions WHERE scope='two'").get().n,1); db.close();
});

test('full profiles and failed profile writes cannot advance suggestion decisions', () => {
  const db = new Database(':memory:'), store = createWatchSuggestions(db), proposals = proposeWatchTerms([report('one')],profile,{now});
  store.list(profile,proposals);
  assert.throws(()=>store.review('one',{...profile,brands:Array.from({length:8},(_,n)=>'term'+n)},proposals[0].id,'accepted',{}),/limite/);
  assert.throws(()=>store.review('one',profile,proposals[0].id,'accepted',{update:()=>{throw Error('disk');}}),/disk/);
  assert.equal(store.list(profile,proposals).length,1);
  store.review('one',profile,proposals[0].id,'dismissed',{}); assert.equal(store.list(profile,proposals).length,0); db.close();
});
