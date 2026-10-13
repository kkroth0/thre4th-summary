// Read-only production audit: public publication evidence and aggregate counts.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import crypto from 'node:crypto';
const root = path.resolve(process.argv[2] || process.cwd());
const read = file => { try { return JSON.parse(fs.readFileSync(file,'utf8')); } catch { return null; } };
const cached = key => read(path.join(root,'server/.feed-cache/rss',crypto.createHash('sha256').update(key).digest('hex')+'.json'));
const archive = read(path.join(root,'server/.news-archive.json')) || [];
const stories = read(path.join(root,'server/.news-stories.json')) || [];
const { actorPublications,buildActorEvidence,buildActorActivity } = await import(pathToFileURL(path.join(root,'server/actorEvidence.js')));
const rows = actorPublications(archive,stories);
const activity = buildActorActivity(rows);
const c2 = archive.find(row => row.repository?.repo?.includes('Unit42') && /C2Agent/i.test(row.title));
const expected = (fs.readFileSync(path.join(root,'server/test/fixtures/c2agent-indicators.txt'),'utf8').match(/\b[a-f0-9]{64}\b/g) || []);
const counts = Object.fromEntries(['ips','domains','hashes','urls'].map(type => [type,new Set(archive.flatMap(row => row.iocs?.[type] || [])).size]));
const ranked = Object.entries(activity).sort((a,b) => b[1].posts-a[1].posts);
const selected = [...new Set(['G0032',...ranked.slice(0,3).map(([id])=>id)])];
const examples = selected.map(id => {
  const profile=buildActorEvidence(rows,id);
  return {actorId:id,counts:profile.counts,example:profile.indicators[0]?.evidence?.[0] || profile.publications[0] || null};
});
const snapshot=cached('newsletter:snapshot');
const bodyStats = Object.fromEntries(['fresh','cached','feed-body','repository-body','deferred','failed','stale'].map(status => [status,(snapshot?.items||[]).filter(row => row.articleCollectionStatus===status).length]));
const sources = stories.flatMap(story=>story.sources||[]);
const indexed=new Map(sources.map(row=>[row.link,row]));
const recent=archive.filter(row=>Date.parse(row.pubDate)>=Date.now()-30*86400000);
const hasIocs=row=>Object.values(row.iocs||{}).some(values=>values?.length);
console.log(JSON.stringify({
  checkedAt:new Date().toISOString(), archivePublications:archive.length,storedStories:stories.length,
  publicationsWithIocs:archive.filter(hasIocs).length,uniqueIocs:counts,
  publicationsWithActors:archive.filter(row=>row.actors?.length).length,
  publicationsWithMalware:archive.filter(row=>row.malware?.length).length,
  publicationsWithCves:archive.filter(row=>row.cves?.length).length,
  actorProfilesWithActivity:Object.keys(activity).length,actorExamples:examples,
  recentArchivePublications:recent.length,recentWithIocs:recent.filter(hasIocs).length,
  recentWithStoryEvidence:recent.filter(row=>indexed.has(row.link)).length,
  extractionVersion:snapshot?.extractionVersion,bodyCollection:bodyStats,
  c2agent:c2 ? {link:c2.link,archivedAt:c2.archivedAt,hashes:c2.iocs?.hashes?.length||0,missingExpectedHashes:expected.filter(hash=>!c2.iocs?.hashes?.includes(hash)).length,
    storyHashes:indexed.get(c2.link)?.iocs?.hashes?.length||0,storyId:c2.storyId} : {status:'not archived yet'},
},null,2));
