// Reagrupa o histórico de histórias com as regras de merge atuais.
//
// mergeIntoStories só reavalia o que chega: o que já está gravado mantém o
// agrupamento do dia em que entrou, por até STORY_RETENTION_DAYS. Depois de
// mudar uma regra, isto reprocessa o arquivo inteiro do zero.
//
//   node server/rebuildStories.mjs            # dry-run, só relata
//   node server/rebuildStories.mjs --write    # grava, com .bak ao lado
//   node server/rebuildStories.mjs --write /outro/.news-stories.json
//
// No servidor, reinicie o serviço DEPOIS de gravar: o processo em execução
// guarda as histórias em memória e as escreve de volta no próximo refresh do
// feed, desfazendo o reagrupamento sem avisar.
//
// Ator e categoria são re-derivados do título antes da remescla: copiá-los da
// história antiga espalharia os atores de um card mal agrupado por todas as
// fontes dele, que é justamente o que estamos desfazendo. Depois da remescla o
// que a história antiga sabia volta, mas só se ela couber inteira numa história
// nova — vide o comentário no meio do arquivo.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mergeIntoStories } from './newsStories.js';
import { buildActorIndex, matchActors } from './actorMatch.js';
import { buildMalwareIndex, matchMalware } from './malwareMatch.js';
import { buildCampaignIndex, matchCampaigns } from './campaignMatch.js';
import { categorize, NEWS_CATEGORIES } from './newsCategories.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const write = args.includes('--write');
const file = args.find((arg) => !arg.startsWith('--')) || path.join(here, '.news-stories.json');

const stories = JSON.parse(fs.readFileSync(file, 'utf8'));
if (!Array.isArray(stories)) throw new Error(`${file} não é uma lista de histórias`);

// Mesma leitura do index.js: o catálogo é {generated_at, actors: [...]}, e
// passar o objeto inteiro constrói um índice vazio, em silêncio.
const catalog = JSON.parse(fs.readFileSync(path.join(here, 'data/actors.json'), 'utf8'));
const index = buildActorIndex(Array.isArray(catalog) ? catalog : catalog.actors);
const malwareCatalog = JSON.parse(fs.readFileSync(path.join(here, 'data/malware.json'), 'utf8'));
const malwareIndex = buildMalwareIndex(Array.isArray(malwareCatalog) ? malwareCatalog : malwareCatalog.malware);
const campaignCatalog = JSON.parse(fs.readFileSync(path.join(here, 'data/campaigns.json'), 'utf8'));
const campaignIndex = buildCampaignIndex(Array.isArray(campaignCatalog) ? campaignCatalog : campaignCatalog.campaigns);
const byLink = new Map();
for (const story of stories) {
    for (const source of story.sources || []) {
        if (!source || !source.link || byLink.has(source.link)) continue;
        const item = {
            title: source.title,
            link: source.link,
            pubDate: source.pubDate,
            source: source.source,
            score: source.score || 0,
            severity: source.severity || null,
            cves: [...(source.cves || [])],
            // A fonte gravada guarda iocs e ttps por artigo (ver newStory() em
            // newsStories.js) — sem isto, um rebuild depois da regra de merge
            // por IOC/TTP perderia essa evidência em silêncio. ttps já são ids
            // (T####), não os rótulos do scoreArticle, então vão direto.
            iocs: source.iocs || null,
            ttpIds: [...(source.ttps || [])],
        };
        item.actors = matchActors(item.title, index);
        item.malware = matchMalware(item.title, malwareIndex);
        item.campaigns = matchCampaigns(item.title, campaignIndex);
        const { categories, primary } = categorize(item);
        item.newsCategories = categories;
        item.primaryCategory = primary;
        byLink.set(source.link, item);
    }
}

const rebuilt = mergeIntoStories([], [...byLink.values()], new Date());

// A fonte gravada não guarda a descrição, então re-derivar pelo título perde
// categoria e ator que vieram do texto do artigo. Devolver o que a história
// antiga sabia só é seguro quando ela coube INTEIRA numa história nova: se foi
// dividida — que é o defeito sendo consertado — o rótulo pode pertencer à outra
// metade, e aí ele fica de fora e espera o próximo refresh do feed.
const storyOfLink = new Map();
for (const story of rebuilt) for (const source of story.sources) storyOfLink.set(source.link, story);

for (const old of stories) {
    const targets = new Set((old.sources || [])
        .map((source) => source && storyOfLink.get(source.link))
        .filter(Boolean));
    if (targets.size !== 1) continue;

    const [target] = targets;
    for (const category of old.categories || []) {
        if (!target.categories.includes(category)) target.categories.push(category);
    }
    for (const actor of old.actors || []) {
        if (actor && actor.id && !target.actors.some((a) => a.id === actor.id)) target.actors.push(actor);
    }
    for (const malware of old.malware || []) {
        if (malware && malware.id && !target.malware.some((m) => m.id === malware.id)) target.malware.push(malware);
    }
    for (const campaign of old.campaigns || []) {
        if (campaign && campaign.id && !target.campaigns.some((c) => c.id === campaign.id)) target.campaigns.push(campaign);
    }
}

// A precedência é a mesma do merge: a principal é a primeira que casou.
for (const story of rebuilt) {
    story.categories = NEWS_CATEGORIES.filter((category) => story.categories.includes(category));
    story.primaryCategory = story.categories[0] || null;
}

const multi = (list) => list.filter((story) => (story.sources || []).length > 1).length;
const cross = (list) => list.filter((story) => new Set((story.sources || []).map((s) => s.source)).size > 1).length;
const withCategory = (list) => list.filter((story) => (story.categories || []).length).length;

console.log(`${file}`);
console.log(`  antes:  ${stories.length} histórias | ${multi(stories)} multi-fonte | ${cross(stories)} entre veículos | ${withCategory(stories)} com categoria`);
console.log(`  depois: ${rebuilt.length} histórias | ${multi(rebuilt)} multi-fonte | ${cross(rebuilt)} entre veículos | ${withCategory(rebuilt)} com categoria`);
console.log(`  fontes: ${byLink.size}`);

if (!write) {
    console.log('\ndry-run — nada foi gravado. Rode com --write para aplicar.');
    process.exit(0);
}

// O .bak fica ao lado: se o reagrupamento sair pior, é um mv de volta.
fs.copyFileSync(file, `${file}.bak`);
fs.writeFileSync(file, JSON.stringify(rebuilt, null, 0));
console.log(`\ngravado. Cópia do anterior em ${file}.bak`);
console.log('reinicie o serviço agora — o processo em execução ainda tem as histórias antigas em memória.');
