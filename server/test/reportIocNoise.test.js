import test from 'node:test';
import assert from 'node:assert/strict';
import {filterReportIocNoise,isReportIocNoise} from '../reportIocNoise.js';
test('report exports exclude repository chrome and documentation without suppressing payload URLs or real domains',()=>{
 const noise=['https://github.com/vendor/iocs','https://raw.githubusercontent.com/vendor/iocs/main/payload.js','github.com','https://lab.example/research/indicators.md','https://lab.example/research/indicators%2eMD?download=1','/research/indicators.md','custom-report.md','https://github.githubassets.com/assets/8zl-a66eb3317210dff0.js','/doc/contributing/first-contributions.md','/doc/contributing/issues.md','/doc/contributing/pull-requests.md','/doc/contributing/large-pull-requests.md','/doc/contributing/ai-guidelines.md','/typings/globals.d.ts','/typings/primordials.d.ts','security.md','governance.md','code-of-conduct.md','ai-guidelines.m'];
 for(const value of noise)assert.equal(isReportIocNoise(value),true,value);
 assert.equal(isReportIocNoise('github.com/vendor/iocs'),true);
 const valid=['https://attacker.workers.dev/assets/payload.js','/api/gate.php?id=1','https://portal.md/','45.148.10.95','https://github.githubassets.com.evil.example/payload.js','https://attacker.github.io/payload'];
 for(const value of valid)assert.equal(isReportIocNoise(value),false,value);
 const report={titulo:'Original',iocs:[...noise,...valid].map(valor=>({valor}))};
 assert.deepEqual(filterReportIocNoise(report).iocs.map(row=>row.valor),valid);assert.equal(report.iocs.length,noise.length+valid.length);
});
