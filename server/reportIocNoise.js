const documentation = new Set(['security.md','first-contributions.md','governance.md','code-of-conduct.md','issues.md','pull-requests.md','large-pull-requests.md','ai-guidelines.md','ai-guidelines.m','readme.md','contributing.md','license.md','changelog.md','globals.d.ts','primordials.d.ts']);
export function isReportIocNoise(value) {
  const clean=String(value||'').trim().toLowerCase().replace(/^hxxp/,'http').replaceAll('[.]','.').replaceAll('(.)','.');
  if(/^https?:\/\//.test(clean)){
    try{const host=new URL(clean).hostname;return host==='githubassets.com'||host.endsWith('.githubassets.com');}catch{return false;}
  }
  const path=clean.split('?')[0];
  return documentation.has(path.split('/').pop())||/^\/(?:doc|docs)\/contributing\//.test(path)||/^\/typings\/.*\.d\.ts$/.test(path)||path==='githubassets.com'||path.endsWith('.githubassets.com');
}
export function filterReportIocNoise(report) {
  return report&&Array.isArray(report.iocs)?{...report,iocs:report.iocs.filter(row=>!isReportIocNoise(row?.valor))}:report;
}
