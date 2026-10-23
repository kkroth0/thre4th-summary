// Editorial preferences apply to weekly suggestions, never to ETL ingestion.
const official = ['cisa.gov','nist.gov','cert.br','cert.europa.eu','microsoft.com','paloaltonetworks.com','talosintelligence.com','cisco.com','fortinet.com','siemens.com','se.com','oracle.com','php.net','nodejs.org','aws.amazon.com','cloud.google.com','securelist.com','welivesecurity.com','trendmicro.com','research.checkpoint.com','crowdstrike.com','sentinelone.com','rapid7.com','claroty.com'];
const press = ['bleepingcomputer.com','thehackernews.com','securityweek.com','securityaffairs.com','securityaffairs.co','therecord.media','darkreading.com','cyberscoop.com','infosecurity-magazine.com','scworld.com','industrialcyber.co','cybersecuritynews.com','cyberpress.org'];
const belongs = (host, domain) => host === domain || host.endsWith('.' + domain);
const normalize = value => String(value || '').normalize('NFKC').toLowerCase();
const contains = (text, value) => {
  const term = normalize(value).trim();
  if (term.length < 3) return false;
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![\\p{L}\\p{N}])${escaped}(?![\\p{L}\\p{N}])`, 'u').test(text);
};
export function weeklyProfileMatches(row, profile) {
  if (!profile) return {assets:[],actors:[],sector:false,ot:false};
  const text=normalize(`${row.title||''} ${row.description||''} ${row.vendor||''} ${row.product||''}`);
  const assets=(profile.assets||[]).filter(asset=>asset.product?contains(text,asset.product):contains(text,asset.vendor)).map(asset=>[asset.vendor,asset.product].filter(Boolean).join(' '));
  const model=profile.threatModel;
  const relevant=new Set(model?.actorIds||profile.actors||[]);
  const known=new Map((model?.actors||[]).map(actor=>[actor.id,actor.name]));
  const actors=[...new Set((row.actors||[]).filter(actor=>typeof actor==='string'?(relevant.has(actor)||[...known].some(([id,name])=>relevant.has(id)&&normalize(name)===normalize(actor))):relevant.has(actor.id)).map(actor=>typeof actor==='string'?(known.get(actor)||actor):known.get(actor.id)||actor.name||actor.id))];
  return {assets:[...new Set(assets)],actors,sector:!!profile.sectors?.some(value=>(row.sectors||[]).includes(value)),ot:!!profile.ot?.present&&(row.categories||row.newsCategories||[]).includes('OT/ICS')};
}
export function weeklyNewsPriority(row, profile) {
  let host;
  try { const url = new URL(row.link); if (!['https:', 'http:'].includes(url.protocol)) return null; host = url.hostname.toLowerCase(); } catch { return null; }
  if (belongs(host, 'medium.com')) return null;
  const text = normalize(`${row.title || ''} ${row.description || ''}`);
  // Inspect the article's language, not the publisher's country or actor origin.
  const script = text.match(/[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}]/gu)?.length || 0;
  const letters = text.match(/\p{L}/gu)?.length || 0;
  if (script >= 8 && script / Math.max(1, letters) > .2) return null;
  const tier = official.some(domain => belongs(host, domain)) ? 'official' : press.some(domain => belongs(host, domain)) ? 'press' : 'other';
  const reasons = tier === 'official' ? ['Fonte oficial / pesquisa do fabricante'] : tier === 'press' ? ['Veículo especializado reconhecido'] : [];
  const context=weeklyProfileMatches(row,profile);
  const matchedAssets = context.assets;
  if (matchedAssets.length) reasons.push(`Ativo do perfil: ${[...new Set(matchedAssets)].slice(0, 3).join(', ')}`);
  const sector = context.sector;
  if (sector) reasons.push('Setor monitorado');
  if(context.actors.length)reasons.push(`Ator relacionado ao perfil: ${context.actors.slice(0,3).join(', ')}`);
  if(context.ot)reasons.push('Ambiente OT/ICS do perfil');
  const majorAsset = /\b(?:microsoft|windows|entra|active directory|exchange|fortinet|fortigate|cisco|palo alto|vmware|sap|oracle|java|php|node\.?js|siemens|schneider|rockwell)\b/i.test(text);
  if (!matchedAssets.length && majorAsset) reasons.push('Tecnologia amplamente utilizada');
  const raw = Math.max(0, Number(row.score) || 0);
  const base = Math.min(raw, 100) + (raw > 100 ? Math.min(5, Math.log10(raw - 99)) : 0);
  const score = base + (tier === 'official' ? 65 : tier === 'press' ? 45 : 0) + (matchedAssets.length ? 60 : majorAsset ? 15 : 0) + (row.kev ? 25 : 0) + (sector ? 15 : 0)+(context.actors.length?40:0)+(context.ot?20:0);
  return {score: Math.round(score * 100) / 100, selectionReasons: reasons, sourceTier: tier};
}
