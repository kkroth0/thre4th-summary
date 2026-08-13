# Notícias em histórias, atores e categorias — Plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** agrupar notícias de fontes diferentes na mesma história persistida, casar cada história com atores de ameaça, segmentar o feed em sete categorias e renomear "Grupos de Ataque" para "Atores de Ameaça".

**Architecture:** quatro módulos puros novos no servidor (`actorMatch`, `newsCategories`, `newsStories`, `newsStoryStore`), costurados num único ponto: `refreshNewsletterFeed()` em `server/index.js`. As regras não tocam disco, rede nem relógio — recebem `now` como argumento e devolvem estado novo, o que as torna testáveis com datas fixas. A lógica de tela vive em `src/pages/newsletterView.ts`, testada por `node --test`, e o JSX fica fino.

**Tech Stack:** Node 20 ESM, `node:test`, Express, React 18, TypeScript 5.8, esbuild, Vite 6.

## Global Constraints

- Nenhuma dependência nova, no servidor ou no front.
- Nenhuma chamada de LLM no caminho de `refreshNewsletterFeed()`.
- `GET /api/newsletter` mantém a forma atual; só ganha campos por item (`storyId`, `actors`, `categories`, `primaryCategory`). O cache em `localStorage` da tela não pode precisar de migração.
- Agrupamento determinístico: a mesma entrada produz o mesmo agrupamento em qualquer execução. Nada de frequência-no-feed-do-dia, nada de `Date.now()` dentro das regras.
- Módulos de regra puros: sem `fs`, sem `axios`, sem `Date.now()`. O tempo entra por parâmetro.
- Persistência no padrão existente: arquivo JSON com `writeJsonAtomic` (`server/index.js:102`), store injetável como `createWatchlistStore`.
- Rotas novas atrás de `requirePremium`, como `/api/newsletter`.
- Retenção de histórias: 60 dias desde `lastSeen`. Janela para unir: 14 dias.
- Testes do servidor rodam por `npm run test:server`; testes do front por `npm run test:unit`.

---

### Task 1: Match de notícia com ator de ameaça

**Files:**
- Create: `server/actorMatch.js`
- Test: `server/test/actorMatch.test.js`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `buildActorIndex(actors) → { distinctive: Map, common: Map }` — `actors` é o array de `server/data/actors.json`, cada um `{ id, name, aliases }`.
  - `matchActors(text, index) → Array<{ id, name, matched, via }>` — `name` é o nome canônico do ator, `matched` é o alias que casou, `via` é `'codename' | 'multiword' | 'context'`.
  - `ACTOR_CONTEXT_TERMS` — o RegExp de contexto, exportado para o teste e para `newsCategories`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `server/test/actorMatch.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildActorIndex, matchActors } from '../actorMatch.js';

const index = buildActorIndex([
    { id: 'a1', name: 'APT28', aliases: ['Sofacy', 'Fancy Bear'] },
    { id: 'a2', name: 'Akira', aliases: [] },
    { id: 'a3', name: 'Scattered Spider', aliases: ['UNC3944'] },
    { id: 'a4', name: '[Unnamed group]', aliases: [] },
    { id: 'a5', name: 'AIZ', aliases: ['XY'] },
]);

const ids = (text) => matchActors(text, index).map((hit) => hit.id).sort();

test('codinome casa em qualquer contexto', () => {
    assert.deepEqual(ids('APT28 targets embassies'), ['a1']);
    assert.deepEqual(ids('Attributed to UNC3944 operators'), ['a3']);
});

test('nome de duas palavras casa sem precisar de contexto', () => {
    assert.deepEqual(ids('Fancy Bear resurfaces in new intrusion'), ['a1']);
    assert.deepEqual(ids('Scattered Spider hits an airline'), ['a3']);
});

test('palavra comum só casa com termo de contexto na mesma frase', () => {
    assert.deepEqual(ids('The Akira ransomware gang leaked the data'), ['a2']);
    assert.deepEqual(ids('Akira Kurosawa retrospective opens today'), []);
    assert.deepEqual(ids('Sofacy analysis published'), []);
    assert.deepEqual(ids('Sofacy APT analysis published'), ['a1']);
});

test('contexto não vaza de uma frase para a outra', () => {
    assert.deepEqual(ids('A new ransomware gang emerged. Akira Kurosawa died in 1998.'), []);
});

test('três caracteres é o piso, não o corte', () => {
    assert.deepEqual(ids('AIZ group claimed it'), ['a5'], 'AIZ tem 3 e fica');
    assert.deepEqual(ids('XY group claimed it'), [], 'XY tem 2 e sai');
    assert.deepEqual(ids('AIZ released a statement'), [], 'palavra comum ainda exige contexto');
});

test('o placeholder de grupo sem nome fica fora do índice', () => {
    assert.deepEqual(ids('[Unnamed group] did it'), []);
});

test('via reporta a regra e o alias que casou', () => {
    assert.deepEqual(matchActors('Fancy Bear strikes', index), [
        { id: 'a1', name: 'APT28', matched: 'Fancy Bear', via: 'multiword' },
    ]);
    assert.deepEqual(matchActors('APT28 strikes', index), [
        { id: 'a1', name: 'APT28', matched: 'APT28', via: 'codename' },
    ]);
    assert.deepEqual(matchActors('the Akira gang', index), [
        { id: 'a2', name: 'Akira', matched: 'Akira', via: 'context' },
    ]);
});

test('o mesmo ator citado duas vezes aparece uma vez só', () => {
    assert.equal(matchActors('APT28 and Sofacy APT are the same group', index).length, 1);
});

test('texto vazio ou nulo não quebra', () => {
    assert.deepEqual(matchActors('', index), []);
    assert.deepEqual(matchActors(null, index), []);
    assert.deepEqual(buildActorIndex(null).distinctive.size, 0);
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

```bash
node --test server/test/actorMatch.test.js
```

Esperado: FAIL, `Cannot find module '../actorMatch.js'`.

- [ ] **Step 3: Implementar o módulo**

Criar `server/actorMatch.js`:

```js
// Actor names are attacker-chosen and often ordinary words — Akira, Reaper,
// Mantis, Elfin. Matching every alias against every headline would attribute a
// Kurosawa retrospective to a ransomware gang, so the index is split in two:
// names that cannot mean anything else, and names that need CTI context nearby.

// Codenames no one uses outside threat intel.
const CODENAME = /^(?:apt-?\d+|apt-[cq]-\d+|unc\d+|tag-\d+|ta\d+|storm-\d+|atk\d+)$/i;

// A common-word alias only counts when one of these sits in the same sentence.
export const ACTOR_CONTEXT_TERMS =
    /\b(?:group|gang|crew|operators?|ransomware|apt|campaign|threat actors?|grupo|quadrilha|campanha)\b/i;

// Below this an "alias" is noise: two letters match half the language.
const MIN_ALIAS_LENGTH = 3;

// The longest actor name worth looking for, in words.
const MAX_GRAM = 4;

const PLACEHOLDER = '[unnamed group]';

const normalize = (value) =>
    String(value || '')
        .toLowerCase()
        .normalize('NFD')
        .replace(/[̀-ͯ]/g, '')
        .trim();

// Hyphens and digits belong to the name (storm-0558, apt-c-36), so they survive.
const tokenize = (value) => normalize(value).split(/[^a-z0-9.@+-]+/).filter(Boolean);

export function buildActorIndex(actors) {
    const distinctive = new Map();
    const common = new Map();
    for (const actor of Array.isArray(actors) ? actors : []) {
        if (!actor || !actor.id) continue;
        for (const raw of [actor.name, ...(actor.aliases || [])]) {
            const alias = String(raw || '').trim();
            const key = normalize(alias);
            if (!key || key === PLACEHOLDER) continue;
            if (alias.replace(/[^a-z0-9]/gi, '').length < MIN_ALIAS_LENGTH) continue;
            const entry = { id: actor.id, name: actor.name, matched: alias };
            if (CODENAME.test(alias)) {
                if (!distinctive.has(key)) distinctive.set(key, { ...entry, via: 'codename' });
            } else if (/\s/.test(alias)) {
                if (!distinctive.has(key)) distinctive.set(key, { ...entry, via: 'multiword' });
            } else if (!common.has(key)) {
                common.set(key, { ...entry, via: 'context' });
            }
        }
    }
    return { distinctive, common };
}

export function matchActors(text, index) {
    const found = new Map();
    // Sentence-scoped: "A ransomware gang emerged. Akira Kurosawa died." must not
    // let the first sentence's context vouch for the second sentence's noun.
    for (const sentence of String(text || '').split(/(?<=[.!?])\s+|[\n\r]+/)) {
        const hasContext = ACTOR_CONTEXT_TERMS.test(sentence);
        const tokens = tokenize(sentence);
        for (let i = 0; i < tokens.length; i++) {
            // Longest gram first, so "Fancy Bear" wins over a hypothetical "Bear".
            for (let n = Math.min(MAX_GRAM, tokens.length - i); n >= 1; n--) {
                const gram = tokens.slice(i, i + n).join(' ');
                const strong = index.distinctive.get(gram);
                if (strong) {
                    if (!found.has(strong.id)) found.set(strong.id, strong);
                    i += n - 1;
                    break;
                }
                const loose = hasContext ? index.common.get(gram) : undefined;
                if (loose) {
                    if (!found.has(loose.id)) found.set(loose.id, loose);
                    i += n - 1;
                    break;
                }
            }
        }
    }
    return [...found.values()];
}
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

```bash
node --test server/test/actorMatch.test.js
```

Esperado: PASS, 8 testes.

- [ ] **Step 5: Conferir contra os dados reais**

```bash
node -e "
const a = require('./server/data/actors.json');
import('./server/actorMatch.js').then(({ buildActorIndex, matchActors }) => {
  const idx = buildActorIndex(Array.isArray(a) ? a : a.actors);
  console.log('distintivos:', idx.distinctive.size, 'comuns:', idx.common.size);
  console.log(matchActors('Akira ransomware gang hits hospital', idx));
  console.log(matchActors('Akira Kurosawa retrospective', idx));
});"
```

Esperado: os dois mapas não vazios; a primeira frase casa Akira, a segunda devolve `[]`. Se a segunda casar algo, um alias de palavra comum escapou para o mapa `distinctive` — conferir a regra `/\s/`.

- [ ] **Step 6: Commit**

```bash
git add server/actorMatch.js server/test/actorMatch.test.js
git commit -m "feat: casar notícia com ator de ameaça sem falso positivo"
```

---

### Task 2: Categorias de notícia

**Files:**
- Create: `server/newsCategories.js`
- Test: `server/test/newsCategories.test.js`

**Interfaces:**
- Consumes: nada de Task 1 em tempo de execução — recebe `item.actors` já preenchido.
- Produces:
  - `NEWS_CATEGORIES` — array das sete categorias, na ordem de precedência.
  - `categorize(item) → { categories: string[], primary: string | null }` — `item` é `{ title, description, threats, cves, actors }`. `categories` sai na ordem de `NEWS_CATEGORIES`; `primary` é a primeira delas, ou `null`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `server/test/newsCategories.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { NEWS_CATEGORIES, categorize } from '../newsCategories.js';

const item = (over = {}) => ({ title: '', description: '', threats: [], cves: [], actors: [], ...over });

test('a ordem de precedência é a acordada', () => {
    assert.deepEqual(NEWS_CATEGORIES, [
        'Ransomware', 'APTs', 'Data Leaks', 'OT/ICS', 'Vulnerabilities', 'Malware', 'Microsoft',
    ]);
});

test('uma história entra em todas as categorias que bateram', () => {
    const result = categorize(item({
        title: 'Cl0p exploits Oracle EBS zero-day',
        threats: ['Ransomware'],
        cves: ['CVE-2025-61882'],
        actors: [{ id: 'a1', name: 'Cl0p', via: 'context' }],
    }));
    assert.deepEqual(result.categories, ['Ransomware', 'Vulnerabilities']);
    assert.equal(result.primary, 'Ransomware', 'a principal sai da precedência');
});

// Cl0p é gangue de ransomware, não APT: um match por contexto não é atribuição
// forte o bastante para carimbar APTs. Só codinome ou nome composto carimba.
test('match por contexto não promove a história a APTs', () => {
    const byContext = categorize(item({ title: 'The Akira gang leaked it', actors: [{ id: 'a', name: 'Akira', via: 'context' }] }));
    assert.ok(!byContext.categories.includes('APTs'));
});

test('APTs vem do match distintivo ou de termo nation-state', () => {
    assert.deepEqual(categorize(item({ title: 'x', actors: [{ id: 'a', name: 'APT28', via: 'codename' }] })).categories, ['APTs']);
    assert.deepEqual(categorize(item({ title: 'A state-sponsored campaign' })).categories, ['APTs']);
});

test('Data Leaks reconhece vazamento em PT e EN', () => {
    assert.ok(categorize(item({ title: 'Data breach exposes 2M customers' })).categories.includes('Data Leaks'));
    assert.ok(categorize(item({ title: 'Vazamento de dados atinge banco' })).categories.includes('Data Leaks'));
});

test('OT/ICS reconhece o vocabulário industrial', () => {
    for (const term of ['SCADA', 'Modbus', 'PLC', 'OPC UA', 'Siemens S7', 'Rockwell']) {
        assert.ok(categorize(item({ title: `Flaw found in ${term} stack` })).categories.includes('OT/ICS'), term);
    }
});

test('Vulnerabilities vem de CVE, de classe de falha ou de exploração ativa', () => {
    assert.ok(categorize(item({ title: 'x', cves: ['CVE-2026-1'] })).categories.includes('Vulnerabilities'));
    assert.ok(categorize(item({ title: 'Remote code execution in the parser' })).categories.includes('Vulnerabilities'));
    assert.ok(categorize(item({ title: 'Bug is actively exploited' })).categories.includes('Vulnerabilities'));
});

test('Malware não inclui ransomware, que tem categoria própria', () => {
    assert.deepEqual(categorize(item({ title: 'x', threats: ['Infostealer'] })).categories, ['Malware']);
    assert.deepEqual(categorize(item({ title: 'x', threats: ['Ransomware'] })).categories, ['Ransomware']);
});

test('Microsoft reconhece a marca e os produtos', () => {
    for (const term of ['Microsoft', 'Windows', 'Exchange', 'SharePoint', 'Azure', 'Entra ID', 'Hyper-V']) {
        assert.ok(categorize(item({ title: `${term} under attack` })).categories.includes('Microsoft'), term);
    }
});

test('item sem nenhum sinal fica sem categoria em vez de cair num balde errado', () => {
    assert.deepEqual(categorize(item({ title: 'Conference agenda published' })), { categories: [], primary: null });
});

test('entrada malformada não quebra', () => {
    assert.deepEqual(categorize(null), { categories: [], primary: null });
    assert.deepEqual(categorize({}), { categories: [], primary: null });
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

```bash
node --test server/test/newsCategories.test.js
```

Esperado: FAIL, `Cannot find module '../newsCategories.js'`.

- [ ] **Step 3: Implementar o módulo**

Criar `server/newsCategories.js`:

```js
// Navigation buckets for the news feed. CTI_CATEGORIES in ctiIntel.js is a
// *scoring* taxonomy — nine overlapping labels that add up to a relevance
// number. These seven are what a reader clicks, so they are separate on purpose.
//
// A story lands in every bucket that matches; `primary` is the first one in this
// order, which is what the card shows. Order is precedence, not importance.
export const NEWS_CATEGORIES = [
    'Ransomware', 'APTs', 'Data Leaks', 'OT/ICS', 'Vulnerabilities', 'Malware', 'Microsoft',
];

const RANSOMWARE = /\b(?:ransomware|double extortion|dupla extors[aã]o|leak site|data leak site|ransom note)\b/i;
const NATION_STATE = /\b(?:nation[- ]state|state[- ]sponsored|state sponsored|advanced persistent threat|cyber ?espionage|espionagem)\b/i;
const DATA_LEAK = /\b(?:data breach|data leak|breached|vazamento de dados|vazamento|exposed \d[\d.,]* (?:records|customers|users))\b/i;
const OT_ICS = /\b(?:ot\/ics|ics\/ot|\bics\b|scada|\bplc\b|\bhmi\b|modbus|opc ua|profinet|dnp3|purdue|safety instrumented|siemens s7|simatic|rockwell|allen[- ]bradley|schneider electric|codesys)\b/i;
const VULN_CLASS = /\b(?:remote code execution|\brce\b|arbitrary code|authentication bypass|auth bypass|privilege escalation|deserialization|path traversal|sql injection|zero[- ]day|0-day|actively exploited|exploited in the wild|proof[- ]of[- ]concept)\b/i;
const MICROSOFT = /\b(?:microsoft|windows|exchange server|exchange online|\bexchange\b|sharepoint|azure|entra id|active directory|office 365|microsoft 365|\bteams\b|outlook|defender|hyper-v)\b/i;

// Malware families that are not ransomware — ransomware has its own bucket.
const MALWARE_THREATS = new Set(['Trojan', 'Infostealer', 'Wiper', 'Backdoor', 'Botnet', 'Spyware', 'Rootkit']);

export function categorize(item) {
    if (!item || typeof item !== 'object') return { categories: [], primary: null };

    const text = `${item.title || ''} ${item.description || ''}`;
    const threats = Array.isArray(item.threats) ? item.threats : [];
    const cves = Array.isArray(item.cves) ? item.cves : [];
    const actors = Array.isArray(item.actors) ? item.actors : [];

    const hits = {
        Ransomware: threats.includes('Ransomware') || RANSOMWARE.test(text),
        // A codename-grade attribution is the strongest APT signal there is.
        APTs: actors.some((a) => a && (a.via === 'codename' || a.via === 'multiword')) || NATION_STATE.test(text),
        'Data Leaks': DATA_LEAK.test(text),
        'OT/ICS': OT_ICS.test(text),
        Vulnerabilities: cves.length > 0 || VULN_CLASS.test(text),
        Malware: threats.some((t) => MALWARE_THREATS.has(t)),
        Microsoft: MICROSOFT.test(text),
    };

    const categories = NEWS_CATEGORIES.filter((name) => hits[name]);
    return { categories, primary: categories[0] || null };
}
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

```bash
node --test server/test/newsCategories.test.js
```

Esperado: PASS, 10 testes.

- [ ] **Step 5: Commit**

```bash
git add server/newsCategories.js server/test/newsCategories.test.js
git commit -m "feat: segmentar notícias em sete categorias navegáveis"
```

---

### Task 3: Agrupamento de itens em histórias

**Files:**
- Create: `server/newsStories.js`
- Test: `server/test/newsStories.test.js`

**Interfaces:**
- Consumes: itens já enriquecidos com `actors` (Task 1) e `categories`/`primaryCategory` (Task 2).
- Produces:
  - `mergeIntoStories(stories, items, now) → Story[]` — puro. `now` é um `Date`. Devolve array novo, ordenado por `lastSeen` decrescente, já podado.
  - `rareTerms(title) → string[]` — exportado para teste.
  - `STORY_RETENTION_DAYS = 60`, `STORY_ACTIVE_DAYS = 14`.
  - Forma de `Story`: `{ id, title, firstSeen, lastSeen, cves, actors, categories, primaryCategory, score, sources: [{ source, link, title, pubDate, score, severity }] }`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `server/test/newsStories.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeIntoStories, rareTerms, STORY_RETENTION_DAYS } from '../newsStories.js';

const NOW = new Date('2026-08-12T12:00:00Z');
const daysBefore = (n) => new Date(NOW.getTime() - n * 86400000).toISOString();

const item = (over = {}) => ({
    title: 'Untitled', description: '', link: `https://x.example/${Math.random()}`,
    source: 'Feed', pubDate: NOW.toISOString(), score: 50, severity: 'High',
    cves: [], actors: [], categories: [], primaryCategory: null, ...over,
});

test('termos raros descartam stopwords e vocabulário comum de segurança', () => {
    assert.deepEqual(rareTerms('New Oracle EBS vulnerability exploited by researchers'), ['oracle']);
    assert.deepEqual(rareTerms('Cl0p exploits Oracle EBS zero-day'), ['cl0p', 'oracle']);
});

test('CVE em comum une, mesmo com títulos sem palavra em comum', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p exploits Oracle EBS', link: 'https://a.example/1', cves: ['CVE-2025-61882'] }),
        item({ title: 'Emergency fix shipped for ERP suite', link: 'https://b.example/2', cves: ['CVE-2025-61882'] }),
    ], NOW);
    assert.equal(stories.length, 1);
    assert.equal(stories[0].sources.length, 2);
});

test('ator em comum une quando há também um termo raro em comum', () => {
    const cl0p = [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }];
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p claims Oracle intrusion', link: 'https://a.example/1', actors: cl0p }),
        item({ title: 'Oracle victims listed by the gang', link: 'https://b.example/2', actors: cl0p }),
    ], NOW);
    assert.equal(stories.length, 1);
});

test('ator em comum sem termo raro em comum não une', () => {
    const cl0p = [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }];
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p claims Oracle intrusion', link: 'https://a.example/1', actors: cl0p }),
        item({ title: 'Cl0p adds Fortra victims', link: 'https://b.example/2', actors: cl0p }),
    ], NOW);
    assert.equal(stories.length, 2);
});

// rareTerms deixa {cl0p, oracle} nos dois títulos: 'exploits', 'flaw', 'abused',
// 'ransomware' e 'zero-day' são vocabulário comum e não contam.
test('Jaccard alto dos termos raros une', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p exploits Oracle EBS zero-day', link: 'https://a.example/1' }),
        item({ title: 'Oracle EBS flaw abused by Cl0p ransomware', link: 'https://b.example/2' }),
    ], NOW);
    assert.equal(stories.length, 1);
});

test('Jaccard exige pelo menos dois termos raros de cada lado', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Oracle patched', link: 'https://a.example/1' }),
        item({ title: 'Oracle updated', link: 'https://b.example/2' }),
    ], NOW);
    assert.equal(stories.length, 2, 'um termo raro de cada lado não é evidência');
});

test('história em silêncio há mais de 14 dias não recebe item novo', () => {
    const old = mergeIntoStories([], [item({ title: 'Cl0p exploits Oracle EBS', link: 'https://a.example/1', cves: ['CVE-1'], pubDate: daysBefore(20) })], new Date(NOW.getTime() - 20 * 86400000));
    const merged = mergeIntoStories(old, [item({ title: 'Cl0p exploits Oracle EBS again', link: 'https://b.example/2', cves: ['CVE-1'] })], NOW);
    assert.equal(merged.length, 2);
});

// A ponte precisa de evidência real dos dois lados: CVE com a primeira
// história, e ator MAIS um termo raro (oracle) com a segunda. Só o nome do
// ator em comum não une — é o que o teste anterior garante.
test('um item que faz a ponte funde duas histórias e mantém o id da mais antiga', () => {
    const seed = mergeIntoStories([], [
        item({ title: 'Oracle EBS emergency patch published', link: 'https://a.example/1', cves: ['CVE-1'], pubDate: daysBefore(3) }),
        item({ title: 'Cl0p leak site lists Oracle victims', link: 'https://b.example/2', actors: [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }], pubDate: daysBefore(2) }),
    ], NOW);
    assert.equal(seed.length, 2);
    const oldestId = seed.find((s) => s.sources[0].link === 'https://a.example/1').id;

    const bridged = mergeIntoStories(seed, [item({
        title: 'Cl0p behind the Oracle EBS attacks', link: 'https://c.example/3',
        cves: ['CVE-1'], actors: [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }],
    })], NOW);
    assert.equal(bridged.length, 1);
    assert.equal(bridged[0].id, oldestId, 'links já compartilhados continuam valendo');
    assert.equal(bridged[0].sources.length, 3);
});

test('o mesmo link não entra duas vezes', () => {
    const one = mergeIntoStories([], [item({ title: 'Cl0p exploits Oracle EBS', link: 'https://a.example/1', cves: ['CVE-1'] })], NOW);
    const twice = mergeIntoStories(one, [item({ title: 'Cl0p exploits Oracle EBS', link: 'https://a.example/1', cves: ['CVE-1'] })], NOW);
    assert.equal(twice[0].sources.length, 1);
});

test('a história herda título e score do item de maior score', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Minor writeup', link: 'https://a.example/1', cves: ['CVE-1'], score: 40 }),
        item({ title: 'CISA issues emergency directive', link: 'https://b.example/2', cves: ['CVE-1'], score: 90 }),
    ], NOW);
    assert.equal(stories[0].title, 'CISA issues emergency directive');
    assert.equal(stories[0].score, 90);
});

test('histórias além da retenção são podadas', () => {
    const long = STORY_RETENTION_DAYS + 5;
    const ancient = mergeIntoStories([], [item({ title: 'Old story about Fortra GoAnywhere', link: 'https://a.example/1', pubDate: daysBefore(long) })], new Date(NOW.getTime() - long * 86400000));
    assert.equal(ancient.length, 1, 'a história existia antes da poda');
    assert.equal(mergeIntoStories(ancient, [], NOW).length, 0);
});

test('determinismo: a mesma entrada duas vezes dá a mesma saída', () => {
    const input = [
        item({ title: 'Cl0p exploits Oracle EBS zero-day', link: 'https://a.example/1' }),
        item({ title: 'Oracle EBS flaw abused by Cl0p ransomware', link: 'https://b.example/2' }),
    ];
    assert.deepEqual(mergeIntoStories([], input, NOW), mergeIntoStories([], input, NOW));
});

test('entrada vazia devolve o estado intacto', () => {
    assert.deepEqual(mergeIntoStories([], [], NOW), []);
    assert.deepEqual(mergeIntoStories(null, null, NOW), []);
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

```bash
node --test server/test/newsStories.test.js
```

Esperado: FAIL, `Cannot find module '../newsStories.js'`.

- [ ] **Step 3: Implementar o módulo**

Criar `server/newsStories.js`:

```js
import crypto from 'node:crypto';

// The same story reaches us from Reuters, BleepingComputer and CISA within
// hours, worded three different ways. De-duplicating by URL — which is all the
// feed did before — keeps all three. Grouping them is what lets a reader follow
// one story instead of re-reading it.
//
// Every rule here is deterministic: the same input has to group the same way
// today and next month, so nothing depends on the current feed's word
// frequencies, on the wall clock, or on iteration order of a Map built elsewhere.

export const STORY_RETENTION_DAYS = 60;
export const STORY_ACTIVE_DAYS = 14;

const DAY = 86400000;
const MIN_RARE_FOR_JACCARD = 2;
const JACCARD_THRESHOLD = 0.5;

// Static, not derived from the day's feed: a frequency-based stoplist would make
// the same pair of headlines group differently tomorrow.
const STOPWORDS = new Set([
    'about', 'after', 'against', 'amid', 'from', 'into', 'over', 'that', 'this', 'their', 'them', 'these', 'those',
    'with', 'without', 'have', 'been', 'were', 'will', 'more', 'most', 'than', 'then', 'they', 'what', 'when', 'which',
    'para', 'pelo', 'pela', 'como', 'mais', 'menos', 'sobre', 'entre', 'apos', 'contra', 'seus', 'suas', 'este', 'esta',
    'isso', 'pode', 'podem', 'sera', 'estao', 'foram',
]);

const COMMON_CTI = new Set([
    'security', 'seguranca', 'vulnerability', 'vulnerabilities', 'vulnerabilidade', 'vulnerabilidades',
    'attack', 'attacks', 'ataque', 'ataques', 'attacker', 'attackers', 'atacante', 'atacantes',
    'flaw', 'flaws', 'falha', 'falhas', 'patch', 'patches', 'patched', 'update', 'updates', 'atualizacao',
    'report', 'reports', 'relatorio', 'research', 'researchers', 'pesquisadores', 'hacker', 'hackers',
    'threat', 'threats', 'ameaca', 'ameacas', 'cyber', 'cyberattack', 'malicious', 'malicioso',
    'exploit', 'exploits', 'exploited', 'exploitation', 'exploracao', 'critical', 'critico', 'critica',
    'warns', 'warning', 'alerta', 'alertam', 'says', 'said', 'novo', 'nova', 'released', 'reveals',
    'bug', 'bugs', 'issue', 'issues', 'code', 'codigo', 'data', 'dados', 'users', 'usuarios',
    // Sit in a large share of CTI headlines, so they carry no grouping signal.
    'ransomware', 'zero-day', '0-day', 'abuse', 'abused', 'abusing', 'targeting', 'targeted',
]);

const normalize = (value) =>
    String(value || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');

export function rareTerms(title) {
    const seen = new Set();
    for (const token of normalize(title).split(/[^a-z0-9-]+/)) {
        if (token.length < 4) continue;
        if (STOPWORDS.has(token) || COMMON_CTI.has(token)) continue;
        seen.add(token);
    }
    return [...seen].sort();
}

const jaccard = (a, b) => {
    if (a.size < MIN_RARE_FOR_JACCARD || b.size < MIN_RARE_FOR_JACCARD) return 0;
    let shared = 0;
    for (const term of a) if (b.has(term)) shared += 1;
    return shared / (a.size + b.size - shared);
};

const overlaps = (a, b) => [...a].some((value) => b.has(value));

const storyId = (link) => crypto.createHash('sha1').update(String(link || '')).digest('hex').slice(0, 12);

const signals = (story) => {
    const rare = new Set(story.sources.flatMap((source) => rareTerms(source.title)));
    // The actor's own name is in both headlines by definition — two unrelated
    // Cl0p stories both say "Cl0p", and that is not evidence they are one story.
    // Rule 2 needs corroboration from somewhere else in the title.
    const actorTokens = new Set(story.actors.flatMap((actor) => rareTerms(`${actor.name} ${actor.matched || ''}`)));
    return {
        cves: new Set(story.cves),
        actors: new Set(story.actors.map((actor) => actor.id)),
        rare,
        rareBeyondActors: new Set([...rare].filter((term) => !actorTokens.has(term))),
    };
};

const isSameStory = (a, b) => {
    if (overlaps(a.cves, b.cves)) return true;
    if (overlaps(a.actors, b.actors) && overlaps(a.rareBeyondActors, b.rareBeyondActors)) return true;
    return jaccard(a.rare, b.rare) >= JACCARD_THRESHOLD;
};

const newStory = (item) => ({
    id: storyId(item.link),
    title: item.title,
    firstSeen: item.pubDate,
    lastSeen: item.pubDate,
    cves: [...(item.cves || [])],
    actors: [...(item.actors || [])],
    categories: [...(item.categories || [])],
    primaryCategory: item.primaryCategory || null,
    score: item.score || 0,
    sources: [{
        source: item.source, link: item.link, title: item.title,
        pubDate: item.pubDate, score: item.score || 0, severity: item.severity || null,
    }],
});

// Absorbs `extra` into `target`, keeping the older identity: a link already
// shared with a colleague has to keep working.
const absorb = (target, extra) => {
    const older = target.firstSeen <= extra.firstSeen ? target : extra;
    const merged = {
        ...target,
        id: older.id,
        firstSeen: older.firstSeen,
        lastSeen: target.lastSeen >= extra.lastSeen ? target.lastSeen : extra.lastSeen,
        cves: [...new Set([...target.cves, ...extra.cves])],
        categories: [...new Set([...target.categories, ...extra.categories])],
        score: Math.max(target.score, extra.score),
        sources: [...target.sources],
    };
    const byId = new Map(target.actors.map((actor) => [actor.id, actor]));
    for (const actor of extra.actors) if (!byId.has(actor.id)) byId.set(actor.id, actor);
    merged.actors = [...byId.values()];

    const links = new Set(target.sources.map((source) => source.link));
    for (const source of extra.sources) if (!links.has(source.link)) merged.sources.push(source);

    // Title and primary category follow the loudest source, which is the one a
    // reader recognises: a CISA directive outranks a two-paragraph writeup.
    const loudest = merged.sources.reduce((best, source) => (source.score > best.score ? source : best), merged.sources[0]);
    merged.title = loudest.title;
    merged.primaryCategory = merged.categories[0] || null;
    return merged;
};

export function mergeIntoStories(stories, items, now) {
    const cutoff = now.getTime() - STORY_RETENTION_DAYS * DAY;
    const activeSince = now.getTime() - STORY_ACTIVE_DAYS * DAY;
    let result = (Array.isArray(stories) ? stories : []).filter((story) => new Date(story.lastSeen).getTime() >= cutoff);

    const known = new Set(result.flatMap((story) => story.sources.map((source) => source.link)));

    // Sorted by date so the merge order — and therefore the surviving id — does
    // not depend on the order the feeds happened to answer in.
    const incoming = (Array.isArray(items) ? items : [])
        .filter((item) => item && item.link && !known.has(item.link))
        .sort((a, b) => String(a.pubDate).localeCompare(String(b.pubDate)) || String(a.link).localeCompare(String(b.link)));

    for (const item of incoming) {
        if (known.has(item.link)) continue;
        known.add(item.link);

        let candidate = newStory(item);
        const rest = [];
        for (const story of result) {
            const active = new Date(story.lastSeen).getTime() >= activeSince;
            // Recomputed each round: absorbing one story hands the candidate a CVE
            // or an actor that can make the next story match too.
            if (active && isSameStory(signals(story), signals(candidate))) {
                candidate = absorb(story, candidate);
            } else {
                rest.push(story);
            }
        }
        rest.push(candidate);
        result = rest;
    }

    return result.sort((a, b) => String(b.lastSeen).localeCompare(String(a.lastSeen)) || a.id.localeCompare(b.id));
}
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

```bash
node --test server/test/newsStories.test.js
```

Esperado: PASS, 13 testes. Se "Jaccard alto" falhar, imprimir `rareTerms` dos dois títulos e conferir se algum termo caiu em `COMMON_CTI` sem dever.

- [ ] **Step 5: Commit**

```bash
git add server/newsStories.js server/test/newsStories.test.js
git commit -m "feat: agrupar notícias de fontes diferentes na mesma história"
```

---

### Task 4: Persistência das histórias

**Files:**
- Create: `server/newsStoryStore.js`
- Test: `server/test/newsStoryStore.test.js`

**Interfaces:**
- Consumes: a forma de `Story` de Task 3.
- Produces: `createStoryStore({ filePath, readFileSync, writeJsonAtomic }) → { all(), save(stories), list({ category, actor, days, limit }), get(id) }`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `server/test/newsStoryStore.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createStoryStore } from '../newsStoryStore.js';

const writeJsonAtomic = (filePath, value) => fs.writeFileSync(filePath, JSON.stringify(value));
const tempFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'news-stories-')), '.news-stories.json');

const story = (over = {}) => ({
    id: 'abc123', title: 'T', firstSeen: '2026-08-01T00:00:00.000Z', lastSeen: '2026-08-10T00:00:00.000Z',
    cves: [], actors: [], categories: ['Ransomware'], primaryCategory: 'Ransomware', score: 50, sources: [], ...over,
});

test('arquivo ausente vira store vazio', () => {
    const store = createStoryStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.deepEqual(store.all(), []);
});

test('arquivo corrompido vira store vazio em vez de derrubar o servidor', () => {
    const filePath = tempFile();
    fs.writeFileSync(filePath, '{ not json');
    const store = createStoryStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.deepEqual(store.all(), []);
});

test('save persiste e recarrega', () => {
    const filePath = tempFile();
    createStoryStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic }).save([story()]);
    const reloaded = createStoryStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.equal(reloaded.all().length, 1);
    assert.equal(reloaded.get('abc123').title, 'T');
});

test('list filtra por categoria, ator e janela de dias', () => {
    const store = createStoryStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    store.save([
        story({ id: 'r1', categories: ['Ransomware'], actors: [{ id: 'a1', name: 'Cl0p' }], lastSeen: '2026-08-11T00:00:00.000Z' }),
        story({ id: 'v1', categories: ['Vulnerabilities'], actors: [], lastSeen: '2026-08-11T00:00:00.000Z' }),
        story({ id: 'old', categories: ['Ransomware'], actors: [], lastSeen: '2026-05-01T00:00:00.000Z' }),
    ]);
    const now = new Date('2026-08-12T00:00:00.000Z');
    assert.deepEqual(store.list({ category: 'Ransomware', now }).map((s) => s.id), ['r1', 'old']);
    assert.deepEqual(store.list({ actor: 'a1', now }).map((s) => s.id), ['r1']);
    assert.deepEqual(store.list({ days: 7, now }).map((s) => s.id).sort(), ['r1', 'v1']);
    assert.equal(store.list({ limit: 1, now }).length, 1);
});

test('get devolve null para id desconhecido', () => {
    const store = createStoryStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.equal(store.get('nope'), null);
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

```bash
node --test server/test/newsStoryStore.test.js
```

Esperado: FAIL, `Cannot find module '../newsStoryStore.js'`.

- [ ] **Step 3: Implementar o módulo**

Criar `server/newsStoryStore.js`:

```js
// File-backed story store, same shape as createWatchlistStore: fs comes in by
// injection so the tests never touch the real state file. A corrupt or missing
// file is an empty store, never a crash — the feed has to keep serving news even
// when the grouping state is gone.
export function createStoryStore({ filePath, readFileSync, writeJsonAtomic }) {
    let stories = [];
    try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
        stories = Array.isArray(parsed) ? parsed.filter((story) => story && story.id && Array.isArray(story.sources)) : [];
    } catch { /* empty store */ }

    return {
        all: () => stories,
        save(next) {
            stories = Array.isArray(next) ? next : [];
            writeJsonAtomic(filePath, stories);
            return stories;
        },
        get: (id) => stories.find((story) => story.id === id) || null,
        list({ category, actor, days, limit, now = new Date() } = {}) {
            let result = stories;
            if (category) result = result.filter((story) => (story.categories || []).includes(category));
            if (actor) result = result.filter((story) => (story.actors || []).some((a) => a.id === actor));
            if (days) {
                const cutoff = now.getTime() - Number(days) * 86400000;
                result = result.filter((story) => new Date(story.lastSeen).getTime() >= cutoff);
            }
            return limit ? result.slice(0, Number(limit)) : result;
        },
    };
}
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

```bash
node --test server/test/newsStoryStore.test.js
```

Esperado: PASS, 5 testes.

- [ ] **Step 5: Rodar a suíte inteira do servidor**

```bash
npm run test:server
```

Esperado: exit 0, sem regressão nas suítes existentes.

- [ ] **Step 6: Commit**

```bash
git add server/newsStoryStore.js server/test/newsStoryStore.test.js
git commit -m "feat: persistir histórias de notícia entre refreshes"
```

---

### Task 5: Costurar no feed e expor as rotas

**Files:**
- Modify: `server/index.js` — imports perto da linha 50, store perto da linha 117, `refreshNewsletterFeed()` em 1643-1719, rotas novas depois de `/api/newsletter` (linha 1751)

**Interfaces:**
- Consumes: `buildActorIndex`/`matchActors` (Task 1), `categorize` (Task 2), `mergeIntoStories` (Task 3), `createStoryStore` (Task 4).
- Produces: itens de `/api/newsletter` com `storyId`, `actors`, `categories`, `primaryCategory`; rotas `GET /api/news/stories` e `GET /api/news/stories/:id`.

- [ ] **Step 1: Adicionar imports e o store**

Em `server/index.js`, junto dos outros imports de módulo local (perto da linha 50):

```js
import { buildActorIndex, matchActors } from './actorMatch.js';
import { categorize } from './newsCategories.js';
import { mergeIntoStories } from './newsStories.js';
import { createStoryStore } from './newsStoryStore.js';
```

Depois de `const dailyEditionStore = ...` (linha 117):

```js
const NEWS_STORIES_PATH = path.join(__dirname, '.news-stories.json');
const newsStoryStore = createStoryStore({ filePath: NEWS_STORIES_PATH, readFileSync: fs.readFileSync, writeJsonAtomic });

// 1840 names and aliases, indexed once at boot rather than per article.
const actorIndex = (() => {
    try {
        const raw = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'actors.json'), 'utf8'));
        return buildActorIndex(Array.isArray(raw) ? raw : raw.actors);
    } catch (error) {
        console.error('actor index unavailable:', error.message);
        return buildActorIndex([]);
    }
})();
```

- [ ] **Step 2: Enriquecer e agrupar dentro de refreshNewsletterFeed**

Em `server/index.js`, em `refreshNewsletterFeed()`, substituir o bloco final:

```js
        // Default order: most recent first (the route can re-sort by relevance).
        const unifiedFeed = items.sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));

        memoryCache.newsletter.data = unifiedFeed;
        memoryCache.newsletter.expiresAt = Date.now() + memoryCache.newsletter.ttl;
```

por:

```js
        // Actor attribution and navigation categories, then grouping. Enrichment
        // must never take the news down with it: on failure the feed still ships,
        // just without storyId.
        for (const item of items) {
            item.actors = matchActors(`${item.title} ${item.description || ''}`, actorIndex);
            const { categories, primary } = categorize(item);
            item.categories = categories;
            item.primaryCategory = primary;
        }

        // Default order: most recent first (the route can re-sort by relevance).
        const unifiedFeed = items.sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));

        try {
            const stories = mergeIntoStories(newsStoryStore.all(), unifiedFeed, new Date());
            newsStoryStore.save(stories);
            const storyByLink = new Map(stories.flatMap((story) => story.sources.map((source) => [source.link, story.id])));
            for (const item of unifiedFeed) item.storyId = storyByLink.get(item.link) || null;
        } catch (error) {
            console.error('news story grouping failed:', error.message);
        }

        memoryCache.newsletter.data = unifiedFeed;
        memoryCache.newsletter.expiresAt = Date.now() + memoryCache.newsletter.ttl;
```

`item.categories` sobrescreve o campo homônimo que `scoreArticle` produzia. Isso é seguro e foi conferido: o campo é declarado em `Newsletter.tsx:47` e copiado do servidor em `Newsletter.tsx:208`, mas nenhuma tela o renderiza. Não há migração de cache a fazer.

- [ ] **Step 3: Adicionar as rotas**

Em `server/index.js`, logo depois do fechamento da rota `app.get('/api/newsletter', ...)` (linha 1751):

```js
// Histórias: o mesmo feed agrupado por assunto, com a linha do tempo de fontes.
//   GET /api/news/stories?category=Ransomware&actor=<id>&days=30&limit=50
app.get('/api/news/stories', requirePremium, async (req, res) => {
    try {
        if (!memoryCache.newsletter.data) await refreshNewsletterFeed();
        res.set('Cache-Control', 'public, max-age=300');
        res.json(newsStoryStore.list({
            category: (req.query.category || '').toString() || undefined,
            actor: (req.query.actor || '').toString() || undefined,
            days: parseInt(req.query.days, 10) || undefined,
            limit: Math.min(parseInt(req.query.limit, 10) || 200, 500),
        }));
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/news/stories/:id', requirePremium, (req, res) => {
    const story = newsStoryStore.get(String(req.params.id));
    if (!story) return res.status(404).json({ error: 'story not found' });
    res.set('Cache-Control', 'public, max-age=300');
    res.json(story);
});
```

- [ ] **Step 4: Verificar que o servidor sobe e as rotas respondem**

```bash
node --check server/index.js && npm run test:server
```

Esperado: exit 0 nos dois.

Depois, subir e conferir o contrato à mão:

```bash
(cd server && node index.js &) && sleep 8 && \
  curl -s localhost:3001/api/newsletter | head -c 400 && echo && \
  curl -s 'localhost:3001/api/news/stories?limit=2' | head -c 400
```

Esperado: `/api/newsletter` devolve itens com `storyId`, `actors`, `categories`, `primaryCategory`; `/api/news/stories` devolve array de histórias. Se as rotas responderem 401/403, a porta ou o `requirePremium` local exige token — conferir `DEPLOYMENT.md` e repetir com o header de auth. Encerrar o processo ao final.

- [ ] **Step 5: Adicionar o arquivo de estado ao .gitignore**

```bash
grep -q '.news-stories.json' .gitignore || echo 'server/.news-stories.json' >> .gitignore
```

Conferir que os outros `.state` do servidor já estão ignorados do mesmo jeito:

```bash
grep -n "server/\." .gitignore
```

- [ ] **Step 6: Commit**

```bash
git add server/index.js .gitignore
git commit -m "feat: agrupar e atribuir o feed de notícias no refresh"
```

---

### Task 6: Lógica de tela das histórias e categorias

**Files:**
- Modify: `src/pages/newsletterView.ts`
- Modify: `src/pages/newsletterView.test.ts`

**Interfaces:**
- Consumes: os campos novos de `/api/newsletter`.
- Produces:
  - `groupAdvisoriesIntoStories(advisories) → StoryCard[]`, onde `StoryCard = { storyId, title, primaryCategory, categories, actors, cves, lastSeen, sources: Advisory[] }`, ordenado por `lastSeen` decrescente.
  - `countByCategory(cards) → Record<string, number>`.
  - `filterStoryCards(cards, { category, actor }) → StoryCard[]`.
  - `NEWS_CATEGORY_ORDER` — as sete na mesma ordem do servidor.

- [ ] **Step 1: Escrever o teste que falha**

Em `src/pages/newsletterView.test.ts`, acrescentar `NEWS_CATEGORY_ORDER`, `countByCategory`, `filterStoryCards` e `groupAdvisoriesIntoStories` ao import que **já existe** de `"./newsletterView"` — não criar um segundo import do mesmo módulo. Depois acrescentar ao fim do arquivo:

```ts
const advisory = (over: Record<string, unknown> = {}) => ({
  title: "T", description: "", link: "https://a.example/1", pubDate: "2026-08-10T00:00:00.000Z",
  source: "Feed", storyId: "s1", actors: [], categories: [], primaryCategory: null, cves: [], ...over,
});

test("itens da mesma história viram um card só, com as fontes dentro", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ link: "https://a.example/1", source: "Reuters", pubDate: "2026-08-10T00:00:00.000Z" }),
    advisory({ link: "https://b.example/2", source: "BleepingComputer", pubDate: "2026-08-11T00:00:00.000Z" }),
  ]);
  assert.equal(cards.length, 1);
  assert.equal(cards[0].sources.length, 2);
  assert.equal(cards[0].lastSeen, "2026-08-11T00:00:00.000Z", "a história é datada pela fonte mais recente");
});

test("item sem storyId continua aparecendo, como card de uma fonte", () => {
  const cards = groupAdvisoriesIntoStories([advisory({ storyId: null, link: "https://c.example/3" })]);
  assert.equal(cards.length, 1);
  assert.equal(cards[0].sources.length, 1);
});

test("o card herda categorias e atores da união das fontes", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ link: "https://a.example/1", categories: ["Ransomware"], actors: [{ id: "a1", name: "Cl0p" }] }),
    advisory({ link: "https://b.example/2", categories: ["Vulnerabilities"], cves: ["CVE-1"] }),
  ]);
  assert.deepEqual(cards[0].categories, ["Ransomware", "Vulnerabilities"]);
  assert.deepEqual(cards[0].actors.map((a) => a.id), ["a1"]);
  assert.deepEqual(cards[0].cves, ["CVE-1"]);
});

test("cards são ordenados pela história mais recente", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "old", link: "https://a.example/1", pubDate: "2026-08-01T00:00:00.000Z" }),
    advisory({ storyId: "new", link: "https://b.example/2", pubDate: "2026-08-11T00:00:00.000Z" }),
  ]);
  assert.deepEqual(cards.map((c) => c.storyId), ["new", "old"]);
});

test("a contagem por categoria conta histórias, não fontes", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "s1", link: "https://a.example/1", categories: ["Ransomware"] }),
    advisory({ storyId: "s1", link: "https://b.example/2", categories: ["Ransomware"] }),
    advisory({ storyId: "s2", link: "https://c.example/3", categories: ["Ransomware", "Microsoft"] }),
  ]);
  assert.equal(countByCategory(cards).Ransomware, 2);
  assert.equal(countByCategory(cards).Microsoft, 1);
});

test("filtro por categoria e por ator", () => {
  const cards = groupAdvisoriesIntoStories([
    advisory({ storyId: "s1", link: "https://a.example/1", categories: ["Ransomware"], actors: [{ id: "a1", name: "Cl0p" }] }),
    advisory({ storyId: "s2", link: "https://b.example/2", categories: ["Microsoft"] }),
  ]);
  assert.deepEqual(filterStoryCards(cards, { category: "Ransomware", actor: "" }).map((c) => c.storyId), ["s1"]);
  assert.deepEqual(filterStoryCards(cards, { category: "", actor: "a1" }).map((c) => c.storyId), ["s1"]);
  assert.equal(filterStoryCards(cards, { category: "", actor: "" }).length, 2);
});

test("a ordem das categorias é a mesma do servidor", () => {
  assert.deepEqual(NEWS_CATEGORY_ORDER, [
    "Ransomware", "APTs", "Data Leaks", "OT/ICS", "Vulnerabilities", "Malware", "Microsoft",
  ]);
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

```bash
./node_modules/.bin/esbuild src/pages/newsletterView.test.ts --bundle --platform=node --format=esm --outfile=/tmp/nv.test.mjs && node --test /tmp/nv.test.mjs
```

Esperado: FAIL, `groupAdvisoriesIntoStories` não existe.

- [ ] **Step 3: Implementar**

Acrescentar ao fim de `src/pages/newsletterView.ts`:

```ts
// Same order as NEWS_CATEGORIES on the server: precedence, not importance.
export const NEWS_CATEGORY_ORDER = [
  "Ransomware", "APTs", "Data Leaks", "OT/ICS", "Vulnerabilities", "Malware", "Microsoft",
] as const;

export interface StoryActor {
  id: string;
  name: string;
  matched?: string;
  via?: string;
}

export interface StorySource {
  link: string;
  source: string;
  title: string;
  pubDate: string;
  storyId?: string | null;
  actors?: StoryActor[];
  categories?: string[];
  primaryCategory?: string | null;
  cves?: string[];
}

export interface StoryCard<T extends StorySource = StorySource> {
  storyId: string;
  title: string;
  primaryCategory: string | null;
  categories: string[];
  actors: StoryActor[];
  cves: string[];
  lastSeen: string;
  sources: T[];
}

// An item with no storyId is its own story. The grouping is enrichment: if the
// server could not group, the reader still sees every headline.
export const groupAdvisoriesIntoStories = <T extends StorySource>(advisories: T[]): StoryCard<T>[] => {
  const byStory = new Map<string, StoryCard<T>>();

  for (const item of advisories) {
    const key = item.storyId || `link:${item.link}`;
    const card = byStory.get(key);
    if (!card) {
      byStory.set(key, {
        storyId: key,
        title: item.title,
        primaryCategory: item.primaryCategory ?? null,
        categories: [...(item.categories ?? [])],
        actors: [...(item.actors ?? [])],
        cves: [...(item.cves ?? [])],
        lastSeen: item.pubDate,
        sources: [item],
      });
      continue;
    }
    card.sources.push(item);
    if (item.pubDate > card.lastSeen) card.lastSeen = item.pubDate;
    for (const category of item.categories ?? []) if (!card.categories.includes(category)) card.categories.push(category);
    for (const cve of item.cves ?? []) if (!card.cves.includes(cve)) card.cves.push(cve);
    for (const actor of item.actors ?? []) if (!card.actors.some((a) => a.id === actor.id)) card.actors.push(actor);
  }

  const cards = [...byStory.values()];
  for (const card of cards) {
    card.categories.sort((a, b) => NEWS_CATEGORY_ORDER.indexOf(a as never) - NEWS_CATEGORY_ORDER.indexOf(b as never));
    card.primaryCategory = card.categories[0] ?? null;
  }
  return cards.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
};

export const countByCategory = (cards: StoryCard[]): Record<string, number> => {
  const counts: Record<string, number> = {};
  for (const card of cards) for (const category of card.categories) counts[category] = (counts[category] ?? 0) + 1;
  return counts;
};

export const filterStoryCards = <T extends StorySource>(
  cards: StoryCard<T>[],
  options: { category: string; actor: string },
): StoryCard<T>[] =>
  cards.filter((card) => {
    if (options.category && !card.categories.includes(options.category)) return false;
    if (options.actor && !card.actors.some((actor) => actor.id === options.actor)) return false;
    return true;
  });
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

```bash
./node_modules/.bin/esbuild src/pages/newsletterView.test.ts --bundle --platform=node --format=esm --outfile=/tmp/nv.test.mjs && node --test /tmp/nv.test.mjs
```

Esperado: PASS, incluindo os testes que já existiam no arquivo.

- [ ] **Step 5: Commit**

```bash
git add src/pages/newsletterView.ts src/pages/newsletterView.test.ts
git commit -m "feat: agrupar o feed em histórias e contar por categoria na tela"
```

---

### Task 7: Tela de Notícias de Segurança

**Files:**
- Modify: `src/pages/Newsletter.tsx` — interface `Advisory` (linha 37-61), estado e filtros (linha 163-432), render da lista (linha 647)

**Interfaces:**
- Consumes: `groupAdvisoriesIntoStories`, `countByCategory`, `filterStoryCards`, `NEWS_CATEGORY_ORDER`, `StoryCard` (Task 6).
- Produces: nada consumido por outra task.

- [ ] **Step 1: Estender o tipo Advisory**

Em `src/pages/Newsletter.tsx`, acrescentar ao fim da interface `Advisory` (linha 60, antes do `}`):

```ts
  // Agrupamento e atribuição, vindos do servidor
  storyId?: string | null;
  actors?: { id: string; name: string; matched?: string; via?: string }[];
  primaryCategory?: string | null;
```

O campo `categories?: string[]` já existe na interface e passa a carregar as sete categorias novas — confirmado na Task 5, Step 2.

- [ ] **Step 2: Montar os cards de história e o estado dos filtros novos**

Depois de `const filteredAdvisories = useMemo(...)` (linha 424), acrescentar:

```tsx
  const [categoryFilter, setCategoryFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");

  const storyCards = useMemo(
    () => filterStoryCards(groupAdvisoriesIntoStories(filteredAdvisories), { category: categoryFilter, actor: actorFilter }),
    [filteredAdvisories, categoryFilter, actorFilter],
  );
  const categoryCounts = useMemo(() => countByCategory(groupAdvisoriesIntoStories(filteredAdvisories)), [filteredAdvisories]);
```

E o import, junto do import existente de `./newsletterView`:

```ts
import { NEWS_CATEGORY_ORDER, countByCategory, filterStoryCards, groupAdvisoriesIntoStories } from "./newsletterView";
```

- [ ] **Step 3: Barra de categorias acima da lista**

Imediatamente antes do bloco que renderiza a lista (linha 630, o ternário `filteredAdvisories.length === 0 ? ... :`):

```tsx
  <div className="flex flex-wrap gap-2 pb-3">
    <button
      type="button"
      onClick={() => setCategoryFilter("")}
      className={`rounded-full border px-3 py-1 text-xs transition ${categoryFilter === "" ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
    >
      {language === "pt" ? "Todas" : "All"}
    </button>
    {NEWS_CATEGORY_ORDER.filter((name) => categoryCounts[name]).map((name) => (
      <button
        key={name}
        type="button"
        onClick={() => setCategoryFilter(categoryFilter === name ? "" : name)}
        className={`rounded-full border px-3 py-1 text-xs transition ${categoryFilter === name ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
      >
        {name} <span className="tabular-nums opacity-60">{categoryCounts[name]}</span>
      </button>
    ))}
  </div>
```

- [ ] **Step 4: Renderizar por história em vez de por item**

Trocar `filteredAdvisories.map((item, idx) => {` (linha 647) por `storyCards.map((card, idx) => {`, e dentro do card usar `const item = card.sources[0];` como o item principal, mantendo todo o corpo existente. Acrescentar, logo abaixo do título do card:

```tsx
  {card.sources.length > 1 && (
    <details className="mt-2">
      <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
        {card.sources.length} {language === "pt" ? "fontes" : "sources"}
        {card.cves.length > 0 && ` · ${language === "pt" ? "unida por" : "linked by"} ${card.cves.join(", ")}`}
        {card.actors.length > 0 && ` · ${card.actors.map((a) => a.name).join(", ")}`}
      </summary>
      <ol className="mt-2 space-y-1 border-l pl-3">
        {[...card.sources].sort((a, b) => a.pubDate.localeCompare(b.pubDate)).map((source) => (
          <li key={source.link} className="text-xs">
            <span className="text-muted-foreground tabular-nums">{new Date(source.pubDate).toLocaleDateString(language === "pt" ? "pt-BR" : "en-US")}</span>
            {" · "}
            <a href={source.link} target="_blank" rel="noopener noreferrer" className="hover:underline">
              {source.source}: {source.title}
            </a>
          </li>
        ))}
      </ol>
    </details>
  )}
  {card.actors.length > 0 && (
    <div className="mt-2 flex flex-wrap gap-1">
      {card.actors.map((actor) => (
        <button
          key={actor.id}
          type="button"
          onClick={() => setActorFilter(actorFilter === actor.id ? "" : actor.id)}
          title={actor.matched && actor.matched !== actor.name ? `${language === "pt" ? "citado como" : "cited as"} ${actor.matched}` : undefined}
          className={`rounded border px-2 py-0.5 text-[11px] transition ${actorFilter === actor.id ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
        >
          {actor.name}
        </button>
      ))}
    </div>
  )}
```

Trocar também a condição de lista vazia na linha 630, de `filteredAdvisories.length === 0` para `storyCards.length === 0`.

- [ ] **Step 5: Verificar tipos, lint e build**

```bash
npm run typecheck && npx eslint src/pages/Newsletter.tsx && npm run build
```

Esperado: exit 0 nos três.

- [ ] **Step 6: Conferir na tela**

```bash
npm run dev
```

Abrir `/newsletter` e confirmar: barra de categorias com contagem; um card com "N fontes" que expande numa linha do tempo por data; chip de ator que filtra ao clicar e desfiltra ao clicar de novo; e que limpar os filtros devolve a lista inteira.

- [ ] **Step 7: Commit**

```bash
git add src/pages/Newsletter.tsx
git commit -m "feat: mostrar notícias agrupadas por história, com categoria e ator"
```

---

### Task 8: Atores de Ameaça — rename e notícias no perfil

**Files:**
- Modify: `src/components/Header.tsx:135`
- Modify: `src/pages/Actors.tsx:937` e o painel de perfil do ator
- Test: `src/pages/actorsView.test.ts`

**Interfaces:**
- Consumes: `GET /api/news/stories?actor=<id>&limit=5` (Task 5).
- Produces: nada consumido por outra task.

- [ ] **Step 1: Escrever o teste que falha**

Em `src/pages/actorsView.test.ts`, acrescentar `actorPageCopy` ao import que **já existe** de `"./actorsView"`. Depois acrescentar ao fim do arquivo:

```ts
test("a página se chama Atores de Ameaça em PT e ES", () => {
  assert.equal(actorPageCopy("pt").title, "Atores de Ameaça");
  assert.equal(actorPageCopy("es").title, "Actores de Amenaza");
  assert.equal(actorPageCopy("en").title, "Threat Actors");
  assert.equal(actorPageCopy("fr").title, "Acteurs de Menace");
});

test("nenhum idioma ainda chama de grupo de ataque", () => {
  for (const language of ["pt", "en", "es", "fr"] as const) {
    assert.doesNotMatch(actorPageCopy(language).title, /grupos? de ataque|groupes? d'attaque/i, language);
  }
});
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

```bash
./node_modules/.bin/esbuild src/pages/actorsView.test.ts --bundle --platform=node --format=esm --outfile=/tmp/av.test.mjs && node --test /tmp/av.test.mjs
```

Esperado: FAIL, `actorPageCopy` não existe.

- [ ] **Step 3: Implementar o rótulo num lugar só**

Acrescentar ao fim de `src/pages/actorsView.ts`:

```ts
// The page and the nav item have to agree, so the label lives here instead of
// being spelled out in both. "Grupos de Ataque" was the old name.
const ACTOR_PAGE_TITLES: Record<string, string> = {
  pt: "Atores de Ameaça",
  en: "Threat Actors",
  es: "Actores de Amenaza",
  fr: "Acteurs de Menace",
};

export const actorPageCopy = (language: string) => ({
  title: ACTOR_PAGE_TITLES[language] ?? ACTOR_PAGE_TITLES.en,
});
```

Em `src/components/Header.tsx:135`, trocar:

```tsx
          label: tr({ pt: "Grupos de Ataque", en: "Threat Actors", es: "Grupos de Ataque", fr: "Groupes d'Attaque" }),
```

por:

```tsx
          label: actorPageCopy(language).title,
```

e importar `actorPageCopy` de `@/pages/actorsView`. `language` já está no escopo, vindo de `const { language, tr } = useLanguage();` em `Header.tsx:68`.

Em `src/pages/Actors.tsx:937`, trocar:

```tsx
              {pt ? "Grupos de Ataque" : "Threat actors"}
```

por:

```tsx
              {actorPageCopy(language).title}
```

- [ ] **Step 4: Rodar o teste e confirmar que passa**

```bash
./node_modules/.bin/esbuild src/pages/actorsView.test.ts --bundle --platform=node --format=esm --outfile=/tmp/av.test.mjs && node --test /tmp/av.test.mjs
```

Esperado: PASS.

- [ ] **Step 5: Bloco "Notícias recentes" no perfil do ator**

Em `src/pages/Actors.tsx`, no painel de perfil (o que já busca `/api/actors/${id}` na linha 846), acrescentar o estado e a busca:

```tsx
  const [actorStories, setActorStories] = useState<{ id: string; title: string; lastSeen: string; sources: { link: string }[] }[]>([]);

  useEffect(() => {
    if (!selectedId) { setActorStories([]); return; }
    let cancelled = false;
    fetch(`/api/news/stories?actor=${encodeURIComponent(selectedId)}&limit=5`)
      .then((response) => (response.ok ? response.json() : []))
      .then((data) => { if (!cancelled) setActorStories(Array.isArray(data) ? data : []); })
      .catch(() => { if (!cancelled) setActorStories([]); });
    return () => { cancelled = true; };
  }, [selectedId]);
```

`selectedId` é o estado que já guarda o ator aberto — o mesmo id passado para `/api/actors/${id}` em `Actors.tsx:846`.

E o bloco, dentro do painel:

```tsx
  {actorStories.length > 0 && (
    <section className="mt-4">
      <h3 className="text-sm font-medium">{pt ? "Notícias recentes" : "Recent news"}</h3>
      <ul className="mt-2 space-y-1">
        {actorStories.map((story) => (
          <li key={story.id} className="text-xs">
            <span className="text-muted-foreground tabular-nums">
              {new Date(story.lastSeen).toLocaleDateString(pt ? "pt-BR" : "en-US")}
            </span>
            {" · "}
            <a href={story.sources[0]?.link} target="_blank" rel="noopener noreferrer" className="hover:underline">
              {story.title}
            </a>
            {story.sources.length > 1 && (
              <span className="ml-1 text-muted-foreground">
                ({story.sources.length} {pt ? "fontes" : "sources"})
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  )}
```

O bloco some quando não há notícia — ator sem cobertura no período é estado normal, não erro.

- [ ] **Step 6: Verificar que o nome antigo sumiu**

```bash
grep -rn "Grupos de Ataque\|Groupes d'Attaque" src/ && echo "AINDA EXISTE" || echo "limpo"
```

Esperado: `limpo`.

- [ ] **Step 7: Rodar tudo**

```bash
npm run test:unit && npm run test:server && npm run typecheck && npx eslint src/ server/ && npm run build
```

Esperado: exit 0 em todos. O eslint pode emitir os avisos pré-existentes de `react-refresh` e `react-hooks/exhaustive-deps`; zero *erros* é o critério.

- [ ] **Step 8: Commit**

```bash
git add src/components/Header.tsx src/pages/Actors.tsx src/pages/actorsView.ts src/pages/actorsView.test.ts
git commit -m "feat: renomear para Atores de Ameaça e listar notícias do ator"
```
