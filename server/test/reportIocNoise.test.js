import test from 'node:test';
import assert from 'node:assert/strict';
import {filterReportIocNoise,isReportIocNoise} from '../reportIocNoise.js';
test('report exports exclude repository chrome and documentation without suppressing payload URLs or real domains',()=>{
 const noise=['https://github.githubassets.com/assets/8zl-a66eb3317210dff0.js','/doc/contributing/first-contributions.md','/doc/contributing/issues.md','/doc/contributing/pull-requests.md','/doc/contributing/large-pull-requests.md','/doc/contributing/ai-guidelines.md','/typings/globals.d.ts','/typings/primordials.d.ts','security.md','governance.md','code-of-conduct.md','ai-guidelines.m'];
 for(const value of noise)assert.equal(isReportIocNoise(value),true,value);
 const valid=['https://attacker.workers.dev/assets/payload.js','/api/gate.php?id=1','portal.md','45.148.10.95','https://github.githubassets.com.evil.example/payload.js','https://raw.githubusercontent.com/actor/repo/main/payload.js'];
 for(const value of valid)assert.equal(isReportIocNoise(value),false,value);
 const report={titulo:'Original',iocs:[...noise,...valid].map(valor=>({valor}))};
 assert.deepEqual(filterReportIocNoise(report).iocs.map(row=>row.valor),valid);assert.equal(report.iocs.length,noise.length+valid.length);
});
