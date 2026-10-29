import test from 'node:test';
import assert from 'node:assert/strict';
import {otxIndicatorUrl} from '../otxLookup.js';

test('OTX routes public IPv4 and IPv6 to their respective indicator endpoints',()=>{
 assert.equal(otxIndicatorUrl('ip','8.8.8.8'),'https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general');
 assert.equal(otxIndicatorUrl('ip','2606:4700:4700::1111'),'https://otx.alienvault.com/api/v1/indicators/IPv6/2606%3A4700%3A4700%3A%3A1111/general');
 assert.throws(()=>otxIndicatorUrl('ip','not-an-ip'));
});

test('non-IP indicator types retain their supported endpoint and cannot introduce a query or redirect',()=>{
 assert.equal(otxIndicatorUrl('domain','example.org'),'https://otx.alienvault.com/api/v1/indicators/domain/example.org/general');
 assert.match(otxIndicatorUrl('hash','a'.repeat(64)),/\/file\/a{64}\/general$/);
 const url=new URL(otxIndicatorUrl('url','https://example.org/A?x=1#fragment'));assert.equal(url.origin,'https://otx.alienvault.com');assert.equal(url.search,'');assert.equal(url.hash,'');assert.match(url.pathname,/https%3A%2F%2Fexample.org%2FA%3Fx%3D1%23fragment/);
});
