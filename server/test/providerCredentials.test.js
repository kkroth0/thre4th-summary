import test from 'node:test';
import assert from 'node:assert/strict';
import { platformProviderCredentials } from '../providerCredentials.js';
import { createCredentialPool } from '../credentialPool.js';
test('expired dedicated keys do not hide the valid configured abuse.ch authentication fallback',async()=>{
 const configured={THREATFOX_API_KEY:['old-secret'],ABUSE_CH_API_KEY:['shared-secret'],MALWAREBAZAAR_API_KEY:['shared-secret']};
 const keys=platformProviderCredentials('threatfox','THREATFOX_API_KEY',env=>configured[env]||[]);
 assert.deepEqual(keys,['old-secret','shared-secret']);const used=[];
 await createCredentialPool().run('threatfox',keys,key=>{used.push(key);if(key==='old-secret')throw {response:{status:401}};return {};});
 assert.deepEqual(used,keys);
 assert.deepEqual(platformProviderCredentials('virustotal','VIRUSTOTAL_API_KEY',()=>['vt-secret']),['vt-secret']);
});
