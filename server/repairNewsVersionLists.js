import { removeVersionIndicators } from './newsQuality.js';
import { rebuildStoryCorrelationsAsync } from './newsStories.js';
import { setImmediate as yieldLoop } from 'node:timers/promises';

// Retire only source-attributed version matches. Independent API observations,
// hashes and publications are untouched. SQLite facades commit both stores
// together, including any aliases/identities affected by splitting an event.
export async function repairNewsVersionLists({archive,stories,bodyFor=()=>'',now=new Date()}) {
    if(archive.publishSnapshot)return archive.publishSnapshot(draft=>repairNewsVersionLists({...draft,bodyFor,now}),stories);
    const archived=archive.all(),retained=stories.all(),byLink=new Map(archived.map(row=>[row.link,row]));
    const candidates=new Map([...retained.flatMap(story=>story.sources),...archived].filter(row=>row.iocs?.ips?.length).map(row=>[row.link,row]));
    const contexts=new Map();let visited=0;
    for(const [link,source] of candidates) {
        const row=byLink.get(link)||source;
        contexts.set(link,[row.title,row.text||row.description,bodyFor(link)].filter(Boolean).join('\n'));
        if(++visited%25===0)await yieldLoop();
    }
    const changed=new Map(),sources=new Map(),removed=new Map();
    const correct=row=>{
        if(!row.iocs?.ips?.length)return null;
        const iocs=removeVersionIndicators(row.iocs,contexts.get(row.link)||'');
        if(iocs.ips.length===row.iocs.ips.length)return null;
        if(!removed.has(row.link))removed.set(row.link,new Set());
        for(const ip of row.iocs.ips)if(!iocs.ips.includes(ip))removed.get(row.link).add(ip);
        return {...row,iocs};
    };
    for(const row of archived){const next=correct(row);if(next)changed.set(row.link,next);}
    for(const row of retained.flatMap(story=>story.sources)){const next=correct(row);if(next)sources.set(row.link,next);}
    if(!removed.size)return {changedPublications:0,retiredMentions:0,rebuiltEvents:0,updates:[]};
    const rebuilt=[];let rebuiltEvents=0;
    for(const story of retained) {
        if(!story.sources.some(source=>sources.has(source.link))){rebuilt.push(story);continue;}
        const corrected={...story,sources:story.sources.map(source=>sources.get(source.link)||source)};
        rebuilt.push(...await rebuildStoryCorrelationsAsync([corrected],[],now));rebuiltEvents++;
    }
    const ids=new Map(rebuilt.flatMap(story=>story.sources.map(source=>[source.link,story.id])));
    const updates=archived.flatMap(row=>{
        const corrected=changed.get(row.link)||row,storyId=ids.get(row.link);
        return changed.has(row.link)||storyId&&storyId!==row.storyId?[{...corrected,...(storyId?{storyId}:{})}]:[];
    });
    archive.add(updates);stories.save(rebuilt);
    return {changedPublications:removed.size,retiredMentions:[...removed.values()].reduce((sum,ips)=>sum+ips.size,0),rebuiltEvents,updates};
}
