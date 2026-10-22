// Opt-in operator smoke test. One public article, isolated in-memory report,
// no account report is created/changed. Provider credentials never leave VPS.
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]||process.cwd());
const local=name=>pathToFileURL(path.join(root,'server',name)).href;
const {default:dotenv}=await import(local('node_modules/dotenv/lib/main.js'));
dotenv.config({path:path.join(root,'.env'),quiet:true});
const {default:http}=await import(local('node_modules/axios/index.js'));
const {createWeeklyEditorial,createWeeklyEditorialGenerator}=await import(local('weeklyEditorial.js'));
const {createWeeklyReports,weeklyWindow}=await import(local('weeklyReports.js'));
const {createPublicationRequest}=await import(local('publicationHttp.js'));
const {extractReadableText}=await import(local('ctiIntel.js'));
const result={configured:!!process.env.OPENROUTER_API_KEY,fixture:true,privateAccountWrites:0};
if(!result.configured){console.log(JSON.stringify(result));process.exitCode=1;}else{
 const now=()=>Date.parse('2026-10-22T17:00:00Z'),range=weeklyWindow(new Date(now()));
 const source='https://nodejs.org/en/blog/vulnerability/october-2026-security-releases';
 const store=createWeeklyReports({now,getInputs:async()=>({publications:[{storyId:'operator-public-article',title:'Node.js October security releases',link:source,source:'Node.js',pubDate:'2026-10-21T12:00:00Z',description:'This feed summary is deliberately too short for editorial writing.'}]})});
 try{
  await store.refresh('isolated');store.select('isolated',range.id,{newsIds:['operator-public-article'],aiNewsIds:[]});
  const request=createPublicationRequest();
  const provider=createWeeklyEditorialGenerator({http,getKey:()=>process.env.OPENROUTER_API_KEY,model:process.env.OPENROUTER_WEEKLY_MODEL||process.env.OPENROUTER_MODEL||'deepseek/deepseek-v4-flash'});
  const diagnostics=[];
  const editorial=createWeeklyEditorial({storage:store.editorialStore,getReport:()=>store.get('isolated',range.id).report,now,
   readArticle:async url=>{const response=await request(url,{maxContentLength:2000000});return {text:extractReadableText(response.data),origin:'article'};},
   generate:async(kind,input,repair)=>{
    try{const value=await provider(kind,input,repair);const normalize=text=>String(text||'').replace(/\s+/g,' ').trim();
     diagnostics.push({kind,repair,keys:Object.keys(value),lengths:Object.fromEntries(['title','lead','context'].map(key=>[key,String(value[key]||'').length])),body:value.body?.map(p=>String(p).length),attention:value.attention?.map(p=>({title:p.title?.length,text:p.text?.length})),quotes:value.supportingQuotes?.map(q=>({characters:normalize(q.text).length,found:input.documents?.some(d=>d.url===q.url&&normalize(d.text).includes(normalize(q.text)))}))});return value;
    }catch(error){diagnostics.push({kind,providerStatus:error.response?.status||error.code||error.name});throw error;}
   },
  });
  editorial.start('isolated',range.id);await editorial.wait('isolated',range.id);
  const state=editorial.status('isolated',store.get('isolated',range.id).report);
  result.status=state.status;result.stories=state.articles?.map(row=>({status:row.status,title:row.title,attention:row.attention?.length,evidence:row.evidence.map(e=>({status:e.status,characters:e.characters,hash:e.hash})),reason:row.reason}));result.sections=!!state.sections;result.diagnostics=diagnostics;
  if(state.status!=='ready')process.exitCode=1;
 }catch{result.status='unavailable';process.exitCode=1;}finally{store.close();}
 console.log(JSON.stringify(result,null,2));
}
