import test from 'node:test';
import assert from 'node:assert/strict';
import {safeUpstreamError} from '../upstreamErrors.js';
test('malformed provider replies and gateway outages are not authentication failures',()=>{
 for(const status of [400,429,500,502,503,504]){const result=safeUpstreamError({response:{status},message:'contains a private credential'});assert.equal(result.status,status);assert.equal(result.code,undefined);assert.ok(!/authentication|configuration|private credential/i.test(result.message));}
});
test('actual credential rejection is structured without exposing the upstream request',()=>{
 for(const error of [{response:{status:401}},{response:{status:403}},{response:{status:502},code:'PROVIDER_AUTH_FAILED'},{noKey:true}]){const result=safeUpstreamError(error);assert.equal(result.status,502);assert.equal(result.code,'PROVIDER_AUTH_FAILED');}
});
