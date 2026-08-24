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
// Ator e categoria são re-derivados do título, não copiados da história antiga:
// um card mal agrupado espalharia os atores dele por todas as fontes, que é
// justamente o que estamos desfazendo. O preço é que a fonte gravada não guarda
// a descrição, então a atribuição sai do título só — o refresh seguinte do feed
// reenriquece com o texto inteiro.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mergeIntoStories } from './newsStories.js';
import { buildActorIndex, matchActors } from './actorMatch.js';
import { categorize } from './newsCategories.js';

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
        };
        item.actors = matchActors(item.title, index);
        const { categories, primary } = categorize(item);
        item.newsCategories = categories;
        item.primaryCategory = primary;
        byLink.set(source.link, item);
    }
}

const rebuilt = mergeIntoStories([], [...byLink.values()], new Date());
const multi = (list) => list.filter((story) => (story.sources || []).length > 1).length;
const cross = (list) => list.filter((story) => new Set((story.sources || []).map((s) => s.source)).size > 1).length;

console.log(`${file}`);
console.log(`  antes:  ${stories.length} histórias | ${multi(stories)} multi-fonte | ${cross(stories)} entre veículos`);
console.log(`  depois: ${rebuilt.length} histórias | ${multi(rebuilt)} multi-fonte | ${cross(rebuilt)} entre veículos`);
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
