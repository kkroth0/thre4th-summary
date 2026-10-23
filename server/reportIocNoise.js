const documentation = new Set(['security.md','first-contributions.md','governance.md','code-of-conduct.md','issues.md','pull-requests.md','large-pull-requests.md','ai-guidelines.md','ai-guidelines.m','readme.md','contributing.md','license.md','changelog.md','globals.d.ts','primordials.d.ts']);
const codeHost = host => ['github.com','githubusercontent.com','githubassets.com'].some(suffix => host === suffix || host.endsWith('.' + suffix));
const markdown = path => /\.(?:md|markdown)$/i.test(path);
export function isReportIocNoise(value) {
  const clean=String(value||'').trim().toLowerCase().replace(/^hxxp/,'http').replaceAll('[.]','.').replaceAll('(.)','.');
  if(/^https?:\/\//.test(clean)){
    try{const url=new URL(clean);let path=url.pathname;try{path=decodeURIComponent(path);}catch{/* retain original path */}return codeHost(url.hostname)||markdown(path);}catch{return false;}
  }
  const path=clean.split('?')[0];
  return markdown(path)||documentation.has(path.split('/').pop())||/^\/(?:doc|docs)\/contributing\//.test(path)||/^\/typings\/.*\.d\.ts$/.test(path)||codeHost(path.split('/')[0]);
}
export function filterReportIocNoise(report) {
  return report&&Array.isArray(report.iocs)?{...report,iocs:report.iocs.filter(row=>!isReportIocNoise(row?.valor))}:report;
}
