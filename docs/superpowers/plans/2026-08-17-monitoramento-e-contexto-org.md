# Configurações de Monitoramento e contexto da organização — Plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** dar ao app um perfil da organização (setor, região, ativos de software, OT) que reordena e explica o feed de Notícias, reunir num só lugar as configurações do que é monitorado, e somar quatro fontes de pesquisa OT.

**Architecture:** o servidor guarda os perfis e deriva, de cada um, um *modelo de ameaças* serializável a partir do catálogo de atores que já está em memória. O casamento notícia↔contexto roda **no cliente**, sobre os campos que cada item do feed já traz — `/api/newsletter` e `/api/news/stories` não mudam em nada. As fontes sem RSS entram por um raspador de listagem que devolve o mesmo formato do parser de RSS existente, então score, atores, categorias e agrupamento vêm de graça.

**Tech Stack:** Node 20 + Express 5 (ESM, `server/`), `cheerio` para raspagem, React 18 + TypeScript + Vite + shadcn/ui (`src/`). Testes: `node:test` para servidor, `esbuild` + `node:test` para o cliente. Nenhuma dependência nova.

**Spec:** `docs/superpowers/specs/2026-08-17-monitoramento-e-contexto-org-design.md`

## Global Constraints

- **Nenhuma dependência nova.** `cheerio` já está em `server/package.json`.
- **Sem LLM** no caminho do refresh do feed.
- `GET /api/newsletter` e `GET /api/news/stories` **não mudam**: nenhum parâmetro novo, nenhum campo novo.
- Módulos de regra são **puros**: sem rede, sem disco, sem `Date.now()` implícito — `now` entra por argumento.
- O perfil **nunca esconde nada por padrão**; o filtro por contexto é opt-in e vem desligado.
- Persistência: `fs` por injeção, `writeJsonAtomic`, arquivo corrompido vira store vazio e nunca derruba o processo. Escreve primeiro, só então avança a memória.
- Perfis são por usuário: toda leitura filtra por `ownerId`; id de outro dono responde **404**, nunca 403.
- Vocabulário fechado: `sectors` só aceita rótulos de `SECTOR_RULES` (`ctiIntel.js`), `regions` só aceita rótulos de `TARGET_REGION_LABELS` (`actorProfile.js`). Valor fora da lista → **400**.
- Limites: 10 perfis/usuário, `name` 1–80, 100 ativos/perfil, campos de ativo 1–60, termo de ativo com no mínimo 3 caracteres alfanuméricos, 30 itens em `ot.vendors`/`ot.protocols` com 40 chars cada, 50 atores fixados.
- Comentários e mensagens de erro em **pt-BR**, no tom dos módulos vizinhos (explicam o *porquê*, não o *o quê*).
- Testes rodam com `npm run test:server` e `npm run test:unit` na raiz do repo.

## Estrutura de arquivos

| Arquivo | Responsabilidade |
|---|---|
| `server/orgProfiles.js` (novo) | validar e persistir perfis |
| `server/orgThreatModel.js` (novo) | derivar o modelo serializável do perfil |
| `server/scrapeFeeds.js` (novo) | fontes de notícia sem RSS |
| `server/actorProfile.js` (modificar) | exportar `TARGET_REGIONS` |
| `server/newsCategories.js` (modificar) | vocabulário OT ampliado |
| `server/ctiIntel.js` (modificar) | somar o RSS do portal Nozomi |
| `server/index.js` (modificar) | rotas `/api/org/*`, ligação do raspador |
| `src/utils/orgRelevance.ts` (novo) | casamento e pesos |
| `src/hooks/useOrgProfile.ts` (novo) | perfil ativo compartilhado |
| `src/services/threatApi.ts` (modificar) | cliente HTTP das rotas novas |
| `src/pages/newsletterView.ts` (modificar) | agregação, ordenação e filtro por contexto |
| `src/pages/Newsletter.tsx` (modificar) | seletor, chip, ordenação, toggle |
| `src/components/settings/OrgProfileEditor.tsx` (novo) | CRUD de perfis |
| `src/components/settings/MonitoringSettings.tsx` (novo) | a aba central |
| `src/components/settings/AdminSettings.tsx` (modificar) | perde o `FeedSourcesManager` |
| `src/pages/Settings.tsx` (modificar) | aba nova |

As tarefas 11–13 (fontes OT) não dependem das tarefas 1–10 e podem ser feitas antes, depois ou em paralelo.

---

### Task 1: Perfis — validação e store

**Files:**
- Create: `server/orgProfiles.js`
- Test: `server/test/orgProfiles.test.js`

**Interfaces:**
- Consumes: `SECTOR_RULES` de `server/ctiIntel.js` (array de `{label, re}`); `TARGET_REGION_LABELS` de `server/actorProfile.js` (array de string).
- Produces: `ORG_LIMITS`, `ORG_SECTORS`, `ORG_REGIONS`, `createOrgError(status, publicMessage)`, `normalizeProfileInput(input, existing, now, owner, knownActorIds)`, `createProfileStore({filePath, readFileSync, writeJsonAtomic})` com `list/get/create/update/remove`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `server/test/orgProfiles.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {
    ORG_LIMITS,
    ORG_REGIONS,
    ORG_SECTORS,
    createProfileStore,
    normalizeProfileInput,
} from '../orgProfiles.js';

const owner = { sub: 'user-1', login: 'analyst' };
const now = '2026-08-17T12:00:00.000Z';

function memoryStore() {
    const files = new Map();
    return createProfileStore({
        filePath: 'profiles.json',
        readFileSync(path) {
            if (!files.has(path)) throw new Error('missing');
            return files.get(path);
        },
        writeJsonAtomic(path, data) { files.set(path, JSON.stringify(data)); },
    });
}

test('o vocabulário sai das listas que o resto do app já produz', () => {
    assert.ok(ORG_SECTORS.includes('Energy'), 'setores vêm de SECTOR_RULES');
    assert.ok(ORG_SECTORS.includes('Manufacturing'));
    assert.ok(ORG_REGIONS.includes('Brazil'), 'regiões vêm de TARGET_REGION_LABELS');
});

test('normaliza um perfil completo', () => {
    const profile = normalizeProfileInput({
        name: '  Cliente X  ',
        sectors: ['Energy', 'Energy'],
        regions: ['Brazil'],
        assets: [{ vendor: ' Fortinet ', product: 'FortiGate' }, { vendor: 'Fortinet', product: 'FortiGate' }],
        ot: { present: true, vendors: ['Siemens'], protocols: ['Modbus'] },
        actors: ['G0034', 'G0034'],
    }, null, now, owner, new Set(['G0034']));

    assert.match(profile.id, /^org_[0-9a-f]{16}$/);
    assert.equal(profile.ownerId, 'user-1');
    assert.equal(profile.ownerLogin, 'analyst');
    assert.equal(profile.name, 'Cliente X');
    assert.deepEqual(profile.sectors, ['Energy'], 'setor repetido entra uma vez');
    assert.deepEqual(profile.assets, [{ vendor: 'Fortinet', product: 'FortiGate' }], 'ativo repetido entra uma vez');
    assert.deepEqual(profile.ot, { present: true, vendors: ['Siemens'], protocols: ['Modbus'] });
    assert.deepEqual(profile.actors, ['G0034']);
    assert.equal(profile.createdAt, now);
    assert.equal(profile.updatedAt, now);
});

test('nome é obrigatório', () => {
    assert.throws(() => normalizeProfileInput({ name: '   ' }, null, now, owner), { status: 400 });
});

// Um setor digitado errado nunca casaria com notícia nenhuma, e o usuário não
// teria como perceber. Falhar alto é o que torna o vocabulário fechado útil.
test('vocabulário fora da lista é rejeitado, não ignorado', () => {
    assert.throws(() => normalizeProfileInput({ name: 'X', sectors: ['Energia'] }, null, now, owner), { status: 400 });
    assert.throws(() => normalizeProfileInput({ name: 'X', regions: ['Brasil'] }, null, now, owner), { status: 400 });
});

// Mesmo motivo do MIN_ALIAS_LENGTH em actorMatch.js: abaixo de 3 caracteres um
// termo casa com meia língua.
test('ativo curto demais é rejeitado', () => {
    assert.throws(() => normalizeProfileInput({ name: 'X', assets: [{ product: 'AD' }] }, null, now, owner), { status: 400 });
});

test('ator inexistente no catálogo é rejeitado', () => {
    assert.throws(
        () => normalizeProfileInput({ name: 'X', actors: ['G9999'] }, null, now, owner, new Set(['G0034'])),
        { status: 400 },
    );
});

test('update preserva id, dono e createdAt', () => {
    const first = normalizeProfileInput({ name: 'A' }, null, now, owner);
    const later = '2026-08-18T12:00:00.000Z';
    const second = normalizeProfileInput({ name: 'B' }, first, later, owner);
    assert.equal(second.id, first.id);
    assert.equal(second.ownerId, 'user-1');
    assert.equal(second.createdAt, now);
    assert.equal(second.updatedAt, later);
    assert.equal(second.name, 'B');
});

test('store isola por dono', () => {
    const store = memoryStore();
    store.create(owner, { name: 'Meu' }, now);
    store.create({ sub: 'user-2', login: 'outro' }, { name: 'Alheio' }, now);

    const mine = store.list('user-1');
    assert.equal(mine.length, 1);
    assert.equal(mine[0].name, 'Meu');
    assert.throws(() => store.get('user-1', store.list('user-2')[0].id), { status: 404 });
    assert.equal(store.remove('user-1', store.list('user-2')[0].id), false);
});

test('store barra no limite de perfis', () => {
    const store = memoryStore();
    for (let i = 0; i < ORG_LIMITS.profilesPerUser; i++) store.create(owner, { name: `P${i}` }, now);
    assert.throws(() => store.create(owner, { name: 'excedente' }, now), { status: 409 });
});

test('arquivo corrompido vira store vazio, não exceção', () => {
    const store = createProfileStore({
        filePath: 'x.json',
        readFileSync: () => '{ isso não é json',
        writeJsonAtomic: () => {},
    });
    assert.deepEqual(store.list('user-1'), []);
});
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `npm run test:server -- --test-name-pattern="perfil|vocabulário|store|ativo|ator|nome"`
Expected: FAIL com `Cannot find module '.../server/orgProfiles.js'`

- [ ] **Step 3: Implementar**

Criar `server/orgProfiles.js`:

```js
// Perfil da organização: o contexto que o app usa para calibrar o que mostra.
//
// Setores e regiões usam exatamente os rótulos que o resto do app já produz —
// SECTOR_RULES em ctiIntel.js carimba `item.sectors` em cada notícia, e
// TARGET_REGIONS em actorProfile.js deriva `actor.targets` de cada ator. Um
// vocabulário próprio aqui exigiria duas tabelas de tradução envelhecendo em
// paralelo, e o join com atores e notícias deixaria de ser de graça.
import crypto from 'crypto';
import { SECTOR_RULES } from './ctiIntel.js';
import { TARGET_REGION_LABELS } from './actorProfile.js';

export const ORG_LIMITS = {
    profilesPerUser: 10,
    nameLength: 80,
    assets: 100,
    assetFieldLength: 60,
    minAssetTerm: 3,
    otList: 30,
    otFieldLength: 40,
    actors: 50,
};

export const ORG_SECTORS = SECTOR_RULES.map((rule) => rule.label);
export const ORG_REGIONS = [...TARGET_REGION_LABELS];

export const createOrgError = (status, publicMessage) =>
    Object.assign(new Error(publicMessage), { status, publicMessage });

const CONTROL_CHARS = /[\x00-\x1F\x7F]/g;
const cleanText = (value, max) =>
    String(value ?? '').replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim().slice(0, max);

const newId = () => `org_${crypto.randomBytes(8).toString('hex')}`;

const fromVocabulary = (values, vocabulary, field) => {
    const out = [];
    for (const raw of Array.isArray(values) ? values : []) {
        const value = cleanText(raw, ORG_LIMITS.nameLength);
        if (!value) continue;
        if (!vocabulary.includes(value)) throw createOrgError(400, `${field} inválido: ${value}`);
        if (!out.includes(value)) out.push(value);
    }
    return out;
};

const normalizeAssets = (values) => {
    const list = Array.isArray(values) ? values : [];
    if (list.length > ORG_LIMITS.assets) throw createOrgError(400, `no máximo ${ORG_LIMITS.assets} ativos por perfil`);
    const out = [];
    const seen = new Set();
    for (const raw of list) {
        const vendor = cleanText(raw?.vendor, ORG_LIMITS.assetFieldLength);
        const product = cleanText(raw?.product, ORG_LIMITS.assetFieldLength);
        if (!vendor && !product) continue;
        for (const term of [vendor, product]) {
            if (term && term.replace(/[^a-z0-9]/gi, '').length < ORG_LIMITS.minAssetTerm) {
                throw createOrgError(400, `ativo curto demais: ${term}`);
            }
        }
        const key = `${vendor.toLowerCase()}|${product.toLowerCase()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ vendor, product });
    }
    return out;
};

const normalizeOt = (value) => {
    const source = value && typeof value === 'object' ? value : {};
    const list = (items) => {
        const arr = Array.isArray(items) ? items : [];
        if (arr.length > ORG_LIMITS.otList) throw createOrgError(400, `no máximo ${ORG_LIMITS.otList} itens em OT`);
        const out = [];
        for (const raw of arr) {
            const item = cleanText(raw, ORG_LIMITS.otFieldLength);
            if (item && !out.includes(item)) out.push(item);
        }
        return out;
    };
    return { present: Boolean(source.present), vendors: list(source.vendors), protocols: list(source.protocols) };
};

/**
 * Valida e normaliza o que o cliente mandou salvar.
 *
 * `knownActorIds` é um Set opcional: quando vem, ids fora do catálogo são
 * rejeitados. Fica como parâmetro para a função continuar pura — quem tem o
 * catálogo é a rota, não este módulo.
 */
export function normalizeProfileInput(input = {}, existing = null, now = new Date().toISOString(), owner = {}, knownActorIds = null) {
    const pick = (key) => (input[key] !== undefined ? input[key] : existing?.[key]);

    const name = cleanText(pick('name'), ORG_LIMITS.nameLength);
    if (!name) throw createOrgError(400, 'nome do perfil é obrigatório');

    const rawActors = Array.isArray(pick('actors')) ? pick('actors') : [];
    if (rawActors.length > ORG_LIMITS.actors) throw createOrgError(400, `no máximo ${ORG_LIMITS.actors} atores fixados`);
    const actors = [];
    for (const raw of rawActors) {
        const id = cleanText(raw, ORG_LIMITS.nameLength);
        if (!id || actors.includes(id)) continue;
        if (knownActorIds && !knownActorIds.has(id)) throw createOrgError(400, `ator desconhecido: ${id}`);
        actors.push(id);
    }

    return {
        id: existing?.id || newId(),
        ownerId: existing?.ownerId || owner.sub,
        ownerLogin: existing?.ownerLogin || owner.login,
        name,
        sectors: fromVocabulary(pick('sectors'), ORG_SECTORS, 'setor'),
        regions: fromVocabulary(pick('regions'), ORG_REGIONS, 'região'),
        assets: normalizeAssets(pick('assets')),
        ot: normalizeOt(pick('ot')),
        actors,
        createdAt: existing?.createdAt || now,
        updatedAt: now,
    };
}

// fs entra por injeção para os testes nunca tocarem o arquivo real. Arquivo
// corrompido ou ausente é store vazio: configurar é acessório, e uma falha aqui
// não pode derrubar o servidor inteiro.
export function createProfileStore({ filePath, readFileSync, writeJsonAtomic }) {
    let profiles = [];
    try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
        profiles = Array.isArray(parsed) ? parsed.filter((p) => p && p.id && p.ownerId) : [];
    } catch { /* store vazio */ }

    // Grava antes de avançar a memória: se writeJsonAtomic estourar (disco
    // cheio, EACCES), a memória não pode ficar à frente do que está no disco.
    const commit = (next) => { writeJsonAtomic(filePath, next); profiles = next; };
    const mine = (ownerId) => profiles.filter((profile) => profile.ownerId === ownerId);

    return {
        list(ownerId) {
            return mine(ownerId).sort((a, b) => String(a.name).localeCompare(String(b.name)));
        },
        // 404 e não 403: confirmar que o id existe já entregaria informação do
        // perfil de outro dono.
        get(ownerId, id) {
            const found = profiles.find((profile) => profile.id === id && profile.ownerId === ownerId);
            if (!found) throw createOrgError(404, 'perfil não encontrado');
            return found;
        },
        create(owner, input, now = new Date().toISOString(), knownActorIds = null) {
            if (mine(owner.sub).length >= ORG_LIMITS.profilesPerUser) {
                throw createOrgError(409, `limite de ${ORG_LIMITS.profilesPerUser} perfis atingido`);
            }
            const profile = normalizeProfileInput(input, null, now, owner, knownActorIds);
            commit([...profiles, profile]);
            return profile;
        },
        update(ownerId, id, input, now = new Date().toISOString(), knownActorIds = null) {
            const current = profiles.find((profile) => profile.id === id && profile.ownerId === ownerId);
            if (!current) throw createOrgError(404, 'perfil não encontrado');
            const next = normalizeProfileInput(input, current, now, { sub: ownerId, login: current.ownerLogin }, knownActorIds);
            commit(profiles.map((profile) => (profile.id === id ? next : profile)));
            return next;
        },
        remove(ownerId, id) {
            const next = profiles.filter((profile) => !(profile.id === id && profile.ownerId === ownerId));
            if (next.length === profiles.length) return false;
            commit(next);
            return true;
        },
    };
}
```

- [ ] **Step 4: Rodar e ver passar**

Run: `npm run test:server`
Expected: PASS, todos os testes existentes continuam verdes.

- [ ] **Step 5: Commit**

```bash
git add server/orgProfiles.js server/test/orgProfiles.test.js
git commit -m "feat: perfis de organização com vocabulário fechado e store por dono"
```

---

### Task 2: Modelo de ameaças do perfil

**Files:**
- Modify: `server/actorProfile.js` (exportar `TARGET_REGIONS`)
- Create: `server/orgThreatModel.js`
- Test: `server/test/orgThreatModel.test.js`

**Interfaces:**
- Consumes: `TARGET_REGIONS` de `server/actorProfile.js` (`{rótulo: string[]}`); perfil no formato produzido por `normalizeProfileInput` (Task 1); atores no formato de `loadActors().actors`, que já chegam com `sectors` e `targets` derivados.
- Produces: `buildThreatModel(profile, actors)` → `{actorIds, pinnedIds, actors:[{id,name,country}], sectors, regions:[{label,terms}], otPresent, assets:[{vendor,product}], techniques}`. Todos os campos são JSON puro — nada de `Set` ou `RegExp`, porque o objeto viaja até o navegador.

- [ ] **Step 1: Escrever o teste que falha**

Criar `server/test/orgThreatModel.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildThreatModel } from '../orgThreatModel.js';

const catalog = [
    { id: 'G0034', name: 'Sandworm', country: 'Russia', sectors: ['Energy'], targets: ['Ukraine'], techniques: [{ id: 'T1486' }] },
    { id: 'G0007', name: 'APT28', country: 'Russia', sectors: ['Government'], targets: ['Brazil'], techniques: [{ id: 'T1566' }, { id: 'T1486' }] },
    { id: 'G0999', name: 'Irrelevante', country: 'China', sectors: ['Retail'], targets: ['Japan'], techniques: [{ id: 'T1059' }] },
];

const profile = (over = {}) => ({ id: 'org_1', name: 'X', sectors: [], regions: [], assets: [], ot: { present: false, vendors: [], protocols: [] }, actors: [], ...over });

test('ator entra pelo setor atacado', () => {
    const model = buildThreatModel(profile({ sectors: ['Energy'] }), catalog);
    assert.deepEqual(model.actorIds, ['G0034']);
});

test('ator entra pela região atacada', () => {
    const model = buildThreatModel(profile({ regions: ['Brazil'] }), catalog);
    assert.deepEqual(model.actorIds, ['G0007']);
});

test('ator fixado entra mesmo sem casar setor ou região', () => {
    const model = buildThreatModel(profile({ actors: ['G0999'] }), catalog);
    assert.deepEqual(model.actorIds, ['G0999']);
    assert.deepEqual(model.pinnedIds, ['G0999']);
});

test('perfil vazio não puxa ator nenhum', () => {
    const model = buildThreatModel(profile(), catalog);
    assert.deepEqual(model.actorIds, []);
    assert.deepEqual(model.techniques, []);
});

test('técnicas são a união dos atores relevantes, sem repetição', () => {
    const model = buildThreatModel(profile({ sectors: ['Energy', 'Government'] }), catalog);
    assert.deepEqual(model.techniques, ['T1486', 'T1566']);
});

// Só o servidor tem o TARGET_REGIONS; o cliente precisa dos termos para casar
// "brazilian" num título. Mandar só as regiões escolhidas mantém isso pequeno.
test('regiões viajam com seus termos, e só as escolhidas', () => {
    const model = buildThreatModel(profile({ regions: ['Brazil'] }), catalog);
    assert.equal(model.regions.length, 1);
    assert.equal(model.regions[0].label, 'Brazil');
    assert.ok(model.regions[0].terms.includes('brazilian'));
});

test('o modelo é JSON puro, porque viaja até o navegador', () => {
    const model = buildThreatModel(profile({ sectors: ['Energy'], assets: [{ vendor: 'Fortinet', product: 'FortiGate' }] }), catalog);
    assert.deepEqual(JSON.parse(JSON.stringify(model)), model);
    assert.deepEqual(model.assets, [{ vendor: 'Fortinet', product: 'FortiGate' }]);
    assert.deepEqual(model.actors, [{ id: 'G0034', name: 'Sandworm', country: 'Russia' }]);
});

test('catálogo ausente não quebra', () => {
    assert.deepEqual(buildThreatModel(profile({ sectors: ['Energy'] }), null).actorIds, []);
    assert.deepEqual(buildThreatModel(null, catalog).actorIds, []);
});
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `npm run test:server`
Expected: FAIL com `Cannot find module '.../server/orgThreatModel.js'`

- [ ] **Step 3: Exportar o mapa de regiões**

Em `server/actorProfile.js`, trocar a declaração da linha 16 de `const TARGET_REGIONS = {` para:

```js
export const TARGET_REGIONS = {
```

Nada mais muda no arquivo: `REGION_RULES` e `TARGET_REGION_LABELS` continuam sendo derivados do mesmo objeto.

- [ ] **Step 4: Implementar o modelo**

Criar `server/orgThreatModel.js`:

```js
// Modelo de ameaças de um perfil: quem ataca gente como você.
//
// Puro sobre o catálogo que loadActors() já mantém em memória — cada ator chega
// com `sectors` e `targets` derivados da descrição por actorProfile.js, então
// não há dado novo a buscar, só um cruzamento.
//
// O retorno é JSON puro porque viaja até o navegador: o casamento notícia↔perfil
// roda no cliente, sobre os campos que o feed já traz.
import { TARGET_REGIONS } from './actorProfile.js';

export function buildThreatModel(profile, actors) {
    const sectors = new Set(profile?.sectors || []);
    const regions = new Set(profile?.regions || []);
    const pinned = new Set(profile?.actors || []);

    const relevant = [];
    for (const actor of Array.isArray(actors) ? actors : []) {
        if (!actor || !actor.id) continue;
        const bySector = (actor.sectors || []).some((sector) => sectors.has(sector));
        const byRegion = (actor.targets || []).some((target) => regions.has(target));
        if (bySector || byRegion || pinned.has(actor.id)) relevant.push(actor);
    }

    const techniques = new Set();
    for (const actor of relevant) {
        for (const technique of actor.techniques || []) if (technique?.id) techniques.add(technique.id);
    }

    return {
        actorIds: relevant.map((actor) => actor.id),
        pinnedIds: relevant.filter((actor) => pinned.has(actor.id)).map((actor) => actor.id),
        actors: relevant.map((actor) => ({ id: actor.id, name: actor.name, country: actor.country || '' })),
        sectors: [...sectors],
        // Os termos vão junto porque só o servidor tem o TARGET_REGIONS, e o
        // cliente precisa deles para reconhecer "brazilian" num título.
        regions: [...regions].map((label) => ({ label, terms: TARGET_REGIONS[label] || [] })),
        otPresent: Boolean(profile?.ot?.present),
        assets: (profile?.assets || []).map((asset) => ({ vendor: asset.vendor || '', product: asset.product || '' })),
        techniques: [...techniques].sort(),
    };
}
```

- [ ] **Step 5: Rodar e ver passar**

Run: `npm run test:server`
Expected: PASS. `actorProfile.test.js` continua verde — a exportação não mudou comportamento.

- [ ] **Step 6: Commit**

```bash
git add server/orgThreatModel.js server/test/orgThreatModel.test.js server/actorProfile.js
git commit -m "feat: derivar o modelo de ameaças de um perfil de organização"
```

---

### Task 3: Rotas de perfil

**Files:**
- Modify: `server/index.js`

**Interfaces:**
- Consumes: `createProfileStore`, `normalizeProfileInput`, `ORG_SECTORS`, `ORG_REGIONS` (Task 1); `buildThreatModel` (Task 2); `loadActors()`, `requireAuth`, `requirePremium`, `sanitizeError`, `writeJsonAtomic`, `exposureStore` — todos já em `server/index.js`.
- Produces: `GET/POST /api/org/profiles`, `PATCH/DELETE /api/org/profiles/:id`, `GET /api/org/profiles/:id/threat-model`, `GET /api/org/vocab`, `GET /api/org/asset-suggestions`.

- [ ] **Step 1: Importar e instanciar o store**

Em `server/index.js`, junto dos outros imports de módulos locais (perto da linha 54, onde entra `actorMatch.js`):

```js
import { ORG_REGIONS, ORG_SECTORS, createProfileStore } from './orgProfiles.js';
import { buildThreatModel } from './orgThreatModel.js';
```

Logo abaixo da criação do `newsStoryStore` (linha ~124):

```js
const ORG_PROFILES_PATH = path.join(__dirname, '.org-profiles.json');
const orgProfileStore = createProfileStore({ filePath: ORG_PROFILES_PATH, readFileSync: fs.readFileSync, writeJsonAtomic });
```

- [ ] **Step 2: Adicionar as rotas**

Inserir logo **antes** de `app.get('/api/actors', ...)` (linha ~3958), porque `loadActors` precisa estar declarado — é um `const` de arrow function, que não sofre hoisting:

```js
// ─── Contexto da organização ───────────────────────────────────────────────
// Configurar não é consumir, então as rotas de perfil pedem só sessão. A de
// sugestões lê o watchlist e herda o requirePremium dele.
const orgError = (res, error) => {
    if (error && error.status && error.publicMessage) {
        return res.status(error.status).json({ error: error.publicMessage });
    }
    const { status, message } = sanitizeError(error);
    res.status(status).json({ error: message });
};

const knownActorIds = () => new Set(loadActors().actors.map((actor) => actor.id));

// Varrer 1362 atores a cada abertura da tela de Notícias é desperdício: o
// perfil só muda quando alguém edita, e updatedAt já marca isso.
const threatModelCache = new Map();
const cachedThreatModel = (profile) => {
    const key = `${profile.id}:${profile.updatedAt}`;
    if (!threatModelCache.has(key)) {
        if (threatModelCache.size > 50) threatModelCache.clear();
        threatModelCache.set(key, buildThreatModel(profile, loadActors().actors));
    }
    return threatModelCache.get(key);
};

app.get('/api/org/vocab', requireAuth, (_req, res) => {
    res.set('Cache-Control', 'private, max-age=3600');
    res.json({ sectors: ORG_SECTORS, regions: ORG_REGIONS });
});

app.get('/api/org/profiles', requireAuth, (req, res) => {
    res.json({ profiles: orgProfileStore.list(req.user.sub) });
});

app.post('/api/org/profiles', requireAuth, (req, res) => {
    try {
        res.status(201).json(orgProfileStore.create(req.user, req.body || {}, new Date().toISOString(), knownActorIds()));
    } catch (error) { orgError(res, error); }
});

app.patch('/api/org/profiles/:id', requireAuth, (req, res) => {
    try {
        res.json(orgProfileStore.update(req.user.sub, String(req.params.id), req.body || {}, new Date().toISOString(), knownActorIds()));
    } catch (error) { orgError(res, error); }
});

app.delete('/api/org/profiles/:id', requireAuth, (req, res) => {
    if (!orgProfileStore.remove(req.user.sub, String(req.params.id))) {
        return res.status(404).json({ error: 'perfil não encontrado' });
    }
    res.json({ ok: true });
});

app.get('/api/org/profiles/:id/threat-model', requireAuth, (req, res) => {
    try {
        res.json(cachedThreatModel(orgProfileStore.get(req.user.sub, String(req.params.id))));
    } catch (error) { orgError(res, error); }
});

// Os produtos detectados ficam em finding.product, dentro dos snapshots — um
// por ativo. Varrer aqui evita um N+1 de requisições no navegador.
app.get('/api/org/asset-suggestions', requirePremium, (req, res) => {
    const byProduct = new Map();
    for (const asset of exposureStore.listAssets(req.user.sub)) {
        const snapshot = exposureStore.previousSuccessfulSnapshot(req.user.sub, asset.id);
        for (const finding of snapshot?.findings || []) {
            const product = String(finding.product || '').trim();
            if (!product) continue;
            const entry = byProduct.get(product.toLowerCase()) || { vendor: '', product, versions: [], seenOn: [] };
            if (finding.version && !entry.versions.includes(finding.version)) entry.versions.push(finding.version);
            if (!entry.seenOn.includes(asset.label)) entry.seenOn.push(asset.label);
            byProduct.set(product.toLowerCase(), entry);
        }
    }
    res.json({ suggestions: [...byProduct.values()].sort((a, b) => a.product.localeCompare(b.product)) });
});
```

- [ ] **Step 3: Verificar que o servidor ainda carrega**

Run: `node --check server/index.js && npm run test:server`
Expected: sem erro de sintaxe, todos os testes passando.

- [ ] **Step 4: Provar as rotas à mão**

Run: `cd server && node index.js` numa aba; noutra, com uma sessão válida no navegador, abrir `http://localhost:3001/api/org/vocab` (ajustar a porta ao que o log imprimir).
Expected: JSON com `sectors` contendo `Energy` e `regions` contendo `Brazil`. Sem sessão: 401.

- [ ] **Step 5: Commit**

```bash
git add server/index.js
git commit -m "feat: rotas de perfil de organização, modelo de ameaças e sugestão de ativos"
```

---

### Task 4: Casamento notícia ↔ contexto (cliente)

**Files:**
- Create: `src/utils/orgRelevance.ts`
- Test: `src/utils/orgRelevance.test.ts`

**Interfaces:**
- Consumes: nada do repo — o módulo é autocontido.
- Produces: `OrgThreatModel`, `OrgMatch`, `OrgRelevance`, `OrgSubject`, `ORG_WEIGHTS`, `orgRelevance(subject, model)`, `annotateOrg(items, model)`.

- [ ] **Step 1: Escrever o teste que falha**

Criar `src/utils/orgRelevance.test.ts`:

```ts
import test from "node:test";
import assert from "node:assert/strict";
import { ORG_WEIGHTS, annotateOrg, orgRelevance, type OrgThreatModel } from "./orgRelevance";

const model = (over: Partial<OrgThreatModel> = {}): OrgThreatModel => ({
  actorIds: [],
  pinnedIds: [],
  actors: [],
  sectors: [],
  regions: [],
  otPresent: false,
  assets: [],
  techniques: [],
  ...over,
});

test("sem modelo, nada é relevante", () => {
  assert.deepEqual(orgRelevance({ title: "FortiGate RCE" }, null), { score: 0, matches: [] });
});

test("ativo do perfil citado no título", () => {
  const result = orgRelevance(
    { title: "Critical RCE in FortiGate appliances" },
    model({ assets: [{ vendor: "Fortinet", product: "FortiGate" }] }),
  );
  assert.equal(result.score, ORG_WEIGHTS.asset);
  assert.deepEqual(result.matches, [{ kind: "asset", label: "FortiGate" }]);
});

// Um termo de 3 letras dentro de outra palavra é exatamente o falso positivo que
// o mínimo de caracteres em orgProfiles.js tenta evitar — a fronteira fecha o resto.
test("ativo curto não casa dentro de outra palavra", () => {
  const result = orgRelevance({ title: "Sapphire Rapids benchmark" }, model({ assets: [{ vendor: "", product: "SAP" }] }));
  assert.equal(result.score, 0);
  assert.deepEqual(orgRelevance({ title: "SAP patch day" }, model({ assets: [{ vendor: "", product: "SAP" }] })).score, ORG_WEIGHTS.asset);
});

test("ator relevante e ator fixado têm pesos diferentes", () => {
  const relevant = model({ actorIds: ["G0034"], actors: [{ id: "G0034", name: "Sandworm", country: "Russia" }] });
  assert.equal(orgRelevance({ title: "x", actors: [{ id: "G0034" }] }, relevant).score, ORG_WEIGHTS.actor);

  const pinnedModel = model({ ...relevant, pinnedIds: ["G0034"] });
  const pinned = orgRelevance({ title: "x", actors: [{ id: "G0034" }] }, pinnedModel);
  assert.equal(pinned.score, ORG_WEIGHTS.actorPinned);
  assert.deepEqual(pinned.matches, [{ kind: "actor", label: "Sandworm", pinned: true }]);
});

test("ator fora do modelo não pontua", () => {
  assert.equal(orgRelevance({ title: "x", actors: [{ id: "G9999" }] }, model({ actorIds: ["G0034"] })).score, 0);
});

test("o mesmo ator repetido conta uma vez", () => {
  const result = orgRelevance(
    { title: "x", actors: [{ id: "G0034" }, { id: "G0034" }] },
    model({ actorIds: ["G0034"], actors: [{ id: "G0034", name: "Sandworm", country: "Russia" }] }),
  );
  assert.equal(result.score, ORG_WEIGHTS.actor);
  assert.equal(result.matches.length, 1);
});

test("setor vem do campo que o servidor já carimba", () => {
  const result = orgRelevance({ title: "x", sectors: ["Energy", "Retail"] }, model({ sectors: ["Energy"] }));
  assert.equal(result.score, ORG_WEIGHTS.sector);
  assert.deepEqual(result.matches, [{ kind: "sector", label: "Energy" }]);
});

test("OT só pontua quando o perfil tem OT", () => {
  const otItem = { title: "x", newsCategories: ["OT/ICS"] };
  assert.equal(orgRelevance(otItem, model({ otPresent: true })).score, ORG_WEIGHTS.ot);
  assert.equal(orgRelevance(otItem, model({ otPresent: false })).score, 0);
});

test("região casa por termo, ignorando acento e caixa", () => {
  const brazil = model({ regions: [{ label: "Brazil", terms: ["brazil", "brazilian"] }] });
  assert.equal(orgRelevance({ title: "Brazilian banks hit" }, brazil).score, ORG_WEIGHTS.region);
  assert.equal(orgRelevance({ title: "BRAZIL under attack" }, brazil).score, ORG_WEIGHTS.region);
  assert.equal(orgRelevance({ title: "Nothing here" }, brazil).score, 0);
});

test("a descrição também é lida", () => {
  const result = orgRelevance({ title: "Advisory", description: "affects FortiGate 7.x" }, model({ assets: [{ vendor: "", product: "FortiGate" }] }));
  assert.equal(result.score, ORG_WEIGHTS.asset);
});

test("a soma tem teto de 100", () => {
  const rich = model({
    assets: [{ vendor: "", product: "FortiGate" }, { vendor: "", product: "ESXi" }],
    actorIds: ["G0034"],
    pinnedIds: ["G0034"],
    actors: [{ id: "G0034", name: "Sandworm", country: "Russia" }],
    sectors: ["Energy"],
    otPresent: true,
    regions: [{ label: "Brazil", terms: ["brazil"] }],
  });
  const result = orgRelevance(
    { title: "FortiGate and ESXi hit in Brazil", sectors: ["Energy"], actors: [{ id: "G0034" }], newsCategories: ["OT/ICS"] },
    rich,
  );
  assert.equal(result.score, 100);
});

test("annotateOrg carimba orgScore e orgMatches sem mexer no resto", () => {
  const items = [{ title: "FortiGate RCE", link: "a" }, { title: "Nada a ver", link: "b" }];
  const annotated = annotateOrg(items, model({ assets: [{ vendor: "", product: "FortiGate" }] }));
  assert.equal(annotated[0].orgScore, ORG_WEIGHTS.asset);
  assert.equal(annotated[0].link, "a");
  assert.equal(annotated[1].orgScore, 0);
  assert.deepEqual(annotated[1].orgMatches, []);
});
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `npm run test:unit`
Expected: FAIL no build do esbuild, `Could not resolve "./orgRelevance"`.

- [ ] **Step 3: Implementar**

Criar `src/utils/orgRelevance.ts`:

```ts
// Casa uma notícia com o contexto da organização.
//
// Roda no cliente de propósito: a tela de Notícias agrupa histórias no
// navegador e guarda até 400 itens em localStorage por dias. Anotar no servidor
// deixaria a anotação velha assim que o usuário trocasse de perfil; recalcular
// aqui reanota os 400 na hora, sem invalidação nenhuma.
//
// Nada de vocabulário próprio: setor vem de `item.sectors` (carimbado por
// scoreArticle), OT vem de `item.newsCategories`, ator vem de `item.actors`, e
// os termos de região vêm dentro do próprio modelo.

export interface OrgThreatModel {
  actorIds: string[];
  pinnedIds: string[];
  actors: { id: string; name: string; country: string }[];
  sectors: string[];
  regions: { label: string; terms: string[] }[];
  otPresent: boolean;
  assets: { vendor: string; product: string }[];
  techniques: string[];
}

export interface OrgMatch {
  kind: "asset" | "actor" | "sector" | "ot" | "region";
  label: string;
  pinned?: boolean;
}

export interface OrgRelevance {
  score: number;
  matches: OrgMatch[];
}

export interface OrgSubject {
  title?: string;
  description?: string;
  actors?: { id: string; name?: string }[];
  sectors?: string[];
  newsCategories?: string[];
}

export const ORG_WEIGHTS = {
  asset: 40,
  actorPinned: 40,
  actor: 30,
  sector: 20,
  ot: 20,
  region: 15,
} as const;

const normalize = (value: string): string =>
  value.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");

const escapeRe = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Fronteira alfanumérica em vez de \b: nomes de produto carregam ponto e hífen
// (Node.js, Allen-Bradley), onde \b cai em lugares errados. Sem lookbehind,
// porque só interessa saber se casou.
const hasTerm = (haystack: string, term: string): boolean => {
  const clean = normalize(term).trim();
  if (!clean) return false;
  return new RegExp(`(^|[^a-z0-9])${escapeRe(clean)}($|[^a-z0-9])`).test(haystack);
};

export const orgRelevance = (subject: OrgSubject, model: OrgThreatModel | null | undefined): OrgRelevance => {
  if (!model) return { score: 0, matches: [] };

  const text = normalize(`${subject.title ?? ""} ${subject.description ?? ""}`);
  const matches: OrgMatch[] = [];
  let score = 0;

  for (const asset of model.assets) {
    const matched = asset.product && hasTerm(text, asset.product)
      ? asset.product
      : asset.vendor && hasTerm(text, asset.vendor)
        ? asset.vendor
        : "";
    if (!matched) continue;
    matches.push({ kind: "asset", label: matched });
    score += ORG_WEIGHTS.asset;
  }

  const relevantActors = new Set(model.actorIds);
  const pinnedActors = new Set(model.pinnedIds);
  const actorName = new Map(model.actors.map((actor) => [actor.id, actor.name]));
  const countedActors = new Set<string>();
  for (const actor of subject.actors ?? []) {
    if (!relevantActors.has(actor.id) || countedActors.has(actor.id)) continue;
    countedActors.add(actor.id);
    const pinned = pinnedActors.has(actor.id);
    matches.push({ kind: "actor", label: actorName.get(actor.id) ?? actor.name ?? actor.id, ...(pinned ? { pinned: true } : {}) });
    score += pinned ? ORG_WEIGHTS.actorPinned : ORG_WEIGHTS.actor;
  }

  const profileSectors = new Set(model.sectors);
  for (const sector of subject.sectors ?? []) {
    if (!profileSectors.has(sector)) continue;
    matches.push({ kind: "sector", label: sector });
    score += ORG_WEIGHTS.sector;
  }

  if (model.otPresent && (subject.newsCategories ?? []).includes("OT/ICS")) {
    matches.push({ kind: "ot", label: "OT/ICS" });
    score += ORG_WEIGHTS.ot;
  }

  for (const region of model.regions) {
    if (!region.terms.some((term) => hasTerm(text, term))) continue;
    matches.push({ kind: "region", label: region.label });
    score += ORG_WEIGHTS.region;
  }

  return { score: Math.min(score, 100), matches };
};

export const annotateOrg = <T extends OrgSubject>(
  items: T[],
  model: OrgThreatModel | null | undefined,
): (T & { orgScore: number; orgMatches: OrgMatch[] })[] =>
  items.map((item) => {
    const { score, matches } = orgRelevance(item, model);
    return { ...item, orgScore: score, orgMatches: matches };
  });
```

- [ ] **Step 4: Rodar e ver passar**

Run: `npm run test:unit && npm run typecheck`
Expected: PASS nos dois.

- [ ] **Step 5: Commit**

```bash
git add src/utils/orgRelevance.ts src/utils/orgRelevance.test.ts
git commit -m "feat: casamento entre notícia e contexto da organização"
```

---

### Task 5: Cliente HTTP e hook do perfil ativo

**Files:**
- Modify: `src/services/threatApi.ts`
- Create: `src/hooks/useOrgProfile.ts`

**Interfaces:**
- Consumes: `OrgThreatModel` de `src/utils/orgRelevance.ts` (Task 4); as rotas da Task 3.
- Produces: `OrgProfile`, `OrgAsset`, `OrgVocab`, `OrgAssetSuggestion`, `fetchOrgProfiles`, `fetchOrgVocab`, `createOrgProfile`, `updateOrgProfile`, `deleteOrgProfile`, `fetchOrgThreatModel`, `fetchOrgAssetSuggestions`; hook `useOrgProfile()` → `{profiles, activeId, setActiveId, active, model, loading, reload}`.

- [ ] **Step 1: Acrescentar as funções de API**

No fim de `src/services/threatApi.ts`:

```ts
// ─── Contexto da organização ───────────────────────────────────────────────
export interface OrgAsset { vendor: string; product: string; }

export interface OrgProfile {
    id: string;
    name: string;
    sectors: string[];
    regions: string[];
    assets: OrgAsset[];
    ot: { present: boolean; vendors: string[]; protocols: string[] };
    actors: string[];
    createdAt: string;
    updatedAt: string;
}

export interface OrgVocab { sectors: string[]; regions: string[]; }
export interface OrgAssetSuggestion { vendor: string; product: string; versions: string[]; seenOn: string[]; }

const orgError = async (response: Response): Promise<never> => {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Falha na requisição (${response.status})`);
};

const orgJson = async <T>(url: string, init?: RequestInit): Promise<T> => {
    const response = await fetch(url, init);
    if (!response.ok) return orgError(response);
    return response.json();
};

export const fetchOrgVocab = (): Promise<OrgVocab> => orgJson('/api/org/vocab');

export const fetchOrgProfiles = async (): Promise<OrgProfile[]> =>
    (await orgJson<{ profiles: OrgProfile[] }>('/api/org/profiles')).profiles;

const jsonBody = (method: string, profile: Partial<OrgProfile>): RequestInit => ({
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(profile),
});

export const createOrgProfile = (profile: Partial<OrgProfile>): Promise<OrgProfile> =>
    orgJson('/api/org/profiles', jsonBody('POST', profile));

export const updateOrgProfile = (id: string, profile: Partial<OrgProfile>): Promise<OrgProfile> =>
    orgJson(`/api/org/profiles/${encodeURIComponent(id)}`, jsonBody('PATCH', profile));

export const deleteOrgProfile = (id: string): Promise<{ ok: boolean }> =>
    orgJson(`/api/org/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' });

export const fetchOrgThreatModel = (id: string): Promise<OrgThreatModel> =>
    orgJson(`/api/org/profiles/${encodeURIComponent(id)}/threat-model`);

export const fetchOrgAssetSuggestions = async (): Promise<OrgAssetSuggestion[]> =>
    (await orgJson<{ suggestions: OrgAssetSuggestion[] }>('/api/org/asset-suggestions')).suggestions;
```

E no topo do arquivo, junto dos outros imports:

```ts
import type { OrgThreatModel } from '@/utils/orgRelevance';
```

- [ ] **Step 2: Criar o hook**

Criar `src/hooks/useOrgProfile.ts`:

```ts
import { useCallback, useEffect, useState } from "react";
import {
  fetchOrgProfiles,
  fetchOrgThreatModel,
  type OrgProfile,
} from "@/services/threatApi";
import type { OrgThreatModel } from "@/utils/orgRelevance";

const STORAGE_KEY = "org.activeProfile";

// O perfil ativo é escolha de quem está na frente da tela, não estado de sessão
// no servidor — por isso mora no localStorage. Quem quiser calibrar outra tela
// pelo contexto chama este hook e passa `model` para orgRelevance.
export function useOrgProfile() {
  const [profiles, setProfiles] = useState<OrgProfile[]>([]);
  const [activeId, setActive] = useState<string>(() => localStorage.getItem(STORAGE_KEY) ?? "");
  const [model, setModel] = useState<OrgThreatModel | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(
    () => fetchOrgProfiles().then(setProfiles).catch(() => setProfiles([])),
    [],
  );

  useEffect(() => { reload().finally(() => setLoading(false)); }, [reload]);

  const setActiveId = useCallback((id: string) => {
    setActive(id);
    if (id) localStorage.setItem(STORAGE_KEY, id);
    else localStorage.removeItem(STORAGE_KEY);
  }, []);

  // Um id apontando para perfil apagado responde 404. Tratar como "sem
  // contexto" e limpar é melhor do que deixar a tela presa num perfil morto.
  useEffect(() => {
    if (!activeId) { setModel(null); return; }
    let cancelled = false;
    fetchOrgThreatModel(activeId)
      .then((next) => { if (!cancelled) setModel(next); })
      .catch(() => { if (!cancelled) { setModel(null); setActiveId(""); } });
    return () => { cancelled = true; };
  }, [activeId, setActiveId]);

  return {
    profiles,
    activeId,
    setActiveId,
    active: profiles.find((profile) => profile.id === activeId) ?? null,
    model,
    loading,
    reload,
  };
}
```

- [ ] **Step 3: Verificar tipos e lint**

Run: `npm run typecheck && npm run lint`
Expected: sem erros.

- [ ] **Step 4: Commit**

```bash
git add src/services/threatApi.ts src/hooks/useOrgProfile.ts
git commit -m "feat: cliente HTTP e hook do perfil de organização ativo"
```

---

### Task 6: Contexto na visão do feed

**Files:**
- Modify: `src/pages/newsletterView.ts`
- Test: `src/pages/newsletterView.test.ts`

**Interfaces:**
- Consumes: `OrgMatch` de `src/utils/orgRelevance.ts` (Task 4).
- Produces: `StorySource` ganha `orgScore?: number` e `orgMatches?: OrgMatch[]`; `StoryCard` ganha `orgScore: number` e `orgMatches: OrgMatch[]`; `groupAdvisoriesIntoStories(advisories, {sortByRelevance?, sortByOrg?})`; `filterStoryCards(cards, {category, actor, orgOnly?})`.

- [ ] **Step 1: Escrever os testes que falham**

Acrescentar ao fim de `src/pages/newsletterView.test.ts`:

```ts
import { filterStoryCards, groupAdvisoriesIntoStories } from "./newsletterView";

const orgItem = (over: Record<string, unknown> = {}) => ({
  link: "l1", source: "S", title: "T", pubDate: "2026-08-17T00:00:00.000Z",
  orgScore: 0, orgMatches: [], ...over,
});

test("a história herda o maior orgScore entre as fontes", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "s1", orgScore: 20, orgMatches: [{ kind: "sector", label: "Energy" }] }),
    orgItem({ link: "b", storyId: "s1", orgScore: 60, orgMatches: [{ kind: "asset", label: "FortiGate" }] }),
  ]);
  assert.equal(cards.length, 1);
  assert.equal(cards[0].orgScore, 60);
  assert.deepEqual(cards[0].orgMatches, [
    { kind: "sector", label: "Energy" },
    { kind: "asset", label: "FortiGate" },
  ]);
});

test("match repetido entre fontes aparece uma vez na história", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "s1", orgScore: 40, orgMatches: [{ kind: "asset", label: "FortiGate" }] }),
    orgItem({ link: "b", storyId: "s1", orgScore: 40, orgMatches: [{ kind: "asset", label: "FortiGate" }] }),
  ]);
  assert.deepEqual(cards[0].orgMatches, [{ kind: "asset", label: "FortiGate" }]);
});

test("sortByOrg ordena pelo contexto, desempatando pelo score do feed", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "a", orgScore: 10, score: 90 }),
    orgItem({ link: "b", storyId: "b", orgScore: 70, score: 10 }),
    orgItem({ link: "c", storyId: "c", orgScore: 70, score: 50 }),
  ], { sortByOrg: true });
  assert.deepEqual(cards.map((card) => card.storyId), ["c", "b", "a"]);
});

test("orgOnly esconde o que está fora do contexto", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "a", orgScore: 40 }),
    orgItem({ link: "b", storyId: "b", orgScore: 0 }),
  ]);
  const filtered = filterStoryCards(cards, { category: "", actor: "", orgOnly: true });
  assert.deepEqual(filtered.map((card) => card.storyId), ["a"]);
});

test("sem orgOnly, nada é escondido — o contexto reordena, não filtra", () => {
  const cards = groupAdvisoriesIntoStories([
    orgItem({ link: "a", storyId: "a", orgScore: 40 }),
    orgItem({ link: "b", storyId: "b", orgScore: 0 }),
  ]);
  assert.equal(filterStoryCards(cards, { category: "", actor: "" }).length, 2);
});
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `npm run test:unit`
Expected: FAIL — `cards[0].orgScore` é `undefined`.

- [ ] **Step 3: Implementar**

Em `src/pages/newsletterView.ts`:

No topo, junto do import de `Language`:

```ts
import type { OrgMatch } from "@/utils/orgRelevance";
```

Em `StorySource`, depois de `score?: number;`:

```ts
  // Relevância para o perfil ativo. Calculada na tela a cada render e nunca
  // persistida: é o que faz trocar de perfil reanotar o cache inteiro.
  orgScore?: number;
  orgMatches?: OrgMatch[];
```

Em `StoryCard`, depois de `score: number;`:

```ts
  orgScore: number;
  orgMatches: OrgMatch[];
```

Na criação do card dentro de `groupAdvisoriesIntoStories`, depois de `score: item.score ?? 0,`:

```ts
        orgScore: item.orgScore ?? 0,
        orgMatches: [...(item.orgMatches ?? [])],
```

Logo depois da linha `if ((item.score ?? 0) > card.score) card.score = item.score ?? 0;`:

```ts
    if ((item.orgScore ?? 0) > card.orgScore) card.orgScore = item.orgScore ?? 0;
    for (const match of item.orgMatches ?? []) {
      if (!card.orgMatches.some((seen) => seen.kind === match.kind && seen.label === match.label)) card.orgMatches.push(match);
    }
```

Na assinatura de opções, trocar `options: { sortByRelevance?: boolean } = {}` por:

```ts
  options: { sortByRelevance?: boolean; sortByOrg?: boolean } = {},
```

E o `return` final da função por:

```ts
  // O contexto manda quando pedido; o score do feed é o desempate, e lastSeen
  // fecha a ordem para ela nunca depender da ordem de chegada.
  if (options.sortByOrg) {
    return cards.sort((a, b) => b.orgScore - a.orgScore || b.score - a.score || b.lastSeen.localeCompare(a.lastSeen));
  }
  return options.sortByRelevance
    ? cards.sort((a, b) => b.score - a.score || b.lastSeen.localeCompare(a.lastSeen))
    : cards.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
```

Em `filterStoryCards`, trocar a assinatura de opções e o corpo:

```ts
export const filterStoryCards = <T extends StorySource>(
  cards: StoryCard<T>[],
  options: { category: string; actor: string; orgOnly?: boolean },
): StoryCard<T>[] =>
  cards.filter((card) => {
    if (options.category && !card.categories.includes(options.category)) return false;
    if (options.actor && !card.actors.some((actor) => actor.id === options.actor)) return false;
    if (options.orgOnly && card.orgScore <= 0) return false;
    return true;
  });
```

- [ ] **Step 4: Rodar e ver passar**

Run: `npm run test:unit && npm run typecheck`
Expected: PASS. Os testes antigos de `newsletterView` continuam verdes — os campos novos têm default.

- [ ] **Step 5: Commit**

```bash
git add src/pages/newsletterView.ts src/pages/newsletterView.test.ts
git commit -m "feat: agregar, ordenar e filtrar histórias pelo contexto da organização"
```

---

### Task 7: Notícias com contexto

**Files:**
- Modify: `src/pages/Newsletter.tsx`

**Interfaces:**
- Consumes: `useOrgProfile` (Task 5), `annotateOrg` e `OrgMatch` (Task 4), `groupAdvisoriesIntoStories`/`filterStoryCards` com as opções novas (Task 6).
- Produces: nada consumido por outras tarefas.

- [ ] **Step 1: Ligar o hook e anotar os itens**

Nos imports do arquivo:

```tsx
import { useOrgProfile } from "@/hooks/useOrgProfile";
import { annotateOrg, type OrgMatch } from "@/utils/orgRelevance";
```

Na interface `Advisory`, depois de `epss?: number;`:

```tsx
  // Preenchidos na tela por annotateOrg; nunca vêm da API nem vão para o cache.
  orgScore?: number;
  orgMatches?: OrgMatch[];
```

Junto dos outros `useState` do componente (perto da linha 174):

```tsx
  const { profiles: orgProfiles, activeId: orgProfileId, setActiveId: setOrgProfileId, model: orgModel } = useOrgProfile();
  const [sortByOrg, setSortByOrg] = useState(false);
  const [orgOnly, setOrgOnly] = useState(false);
```

Trocar o `useMemo` de `filteredAdvisories` (linha ~433) para anotar depois de filtrar:

```tsx
  const filteredAdvisories = useMemo(() => annotateOrg(filterNewsletterAdvisories(advisories, {
    search: searchNews,
    layer: selectedLayer,
    severity: selectedSeverity,
    kevOnly,
    sortByRelevance,
  }), orgModel), [advisories, searchNews, selectedLayer, selectedSeverity, kevOnly, sortByRelevance, orgModel]);
```

> Conferir os nomes das chaves contra o objeto que já está no arquivo antes de colar — o que muda é só o `annotateOrg(...)` em volta e o `orgModel` na lista de dependências.

E o `useMemo` de `storyCards` (linha ~445):

```tsx
  const storyCards = useMemo(
    () => filterStoryCards(
      groupAdvisoriesIntoStories(filteredAdvisories, { sortByRelevance, sortByOrg: sortByOrg && Boolean(orgModel) }),
      { category: categoryFilter, actor: actorFilter, orgOnly: orgOnly && Boolean(orgModel) },
    ),
    [filteredAdvisories, sortByRelevance, sortByOrg, orgModel, categoryFilter, actorFilter, orgOnly],
  );
```

- [ ] **Step 2: Seletor de perfil e toggles**

Dentro do popover de filtros, junto dos controles existentes (perto da linha 519–608, antes do botão "Limpar filtros"), e **só quando o usuário tem perfil**:

```tsx
                  {orgProfiles.length > 0 && (
                    <div className="space-y-2 border-t pt-3">
                      <label className="text-xs font-medium text-muted-foreground">
                        {language === "pt" ? "Contexto da organização" : "Organization context"}
                      </label>
                      <select
                        value={orgProfileId}
                        onChange={(event) => setOrgProfileId(event.target.value)}
                        className="w-full rounded-md border bg-background px-2 py-1.5 text-xs"
                      >
                        <option value="">{language === "pt" ? "Sem contexto" : "No context"}</option>
                        {orgProfiles.map((profile) => (
                          <option key={profile.id} value={profile.id}>{profile.name}</option>
                        ))}
                      </select>
                      <label className="flex items-center gap-2 text-xs">
                        <input type="checkbox" checked={sortByOrg} disabled={!orgModel} onChange={(event) => setSortByOrg(event.target.checked)} />
                        {language === "pt" ? "Relevante para mim primeiro" : "Most relevant to me first"}
                      </label>
                      <label className="flex items-center gap-2 text-xs">
                        <input type="checkbox" checked={orgOnly} disabled={!orgModel} onChange={(event) => setOrgOnly(event.target.checked)} />
                        {language === "pt" ? "Só o meu contexto" : "My context only"}
                      </label>
                    </div>
                  )}
```

- [ ] **Step 3: Chip no card**

Na linha de badges do card, logo depois do bloco `{item.kev && (...)}` (perto da linha 730), usando `card` e não `item` — a relevância é da história inteira:

```tsx
                            {card.orgScore > 0 && (
                              <Badge
                                variant="outline"
                                title={language === "pt" ? "Casa com o contexto da organização" : "Matches your organization context"}
                                className="text-[10px] font-semibold bg-primary/10 text-primary border-primary/30"
                              >
                                {language === "pt" ? "Relevante" : "Relevant"}
                                <span className="ml-1 font-normal opacity-80">
                                  {card.orgMatches.slice(0, 3).map((match) => match.label).join(" · ")}
                                </span>
                              </Badge>
                            )}
```

- [ ] **Step 4: Contar o contexto no badge de filtros ativos**

No array que conta filtros ativos (perto da linha 450–456), acrescentar dois itens:

```tsx
    sortByOrg,
    orgOnly,
```

- [ ] **Step 5: Verificar**

Run: `npm run typecheck && npm run lint && npm run build`
Expected: sem erros nos três.

- [ ] **Step 6: Provar na tela**

Run: `npm run server` numa aba e `npm run dev` noutra. Logar, criar um perfil pela API (`curl -X POST /api/org/profiles`) ou esperar a Task 9, abrir `/newsletter`, escolher o perfil no popover de filtros.
Expected: o chip "Relevante" aparece nas histórias que casam; "Relevante para mim primeiro" reordena; "Só o meu contexto" encurta a lista; escolher "Sem contexto" devolve a tela ao estado original.

- [ ] **Step 7: Commit**

```bash
git add src/pages/Newsletter.tsx
git commit -m "feat: reordenar e explicar as notícias pelo contexto da organização"
```

---

### Task 8: Editor de perfis

**Files:**
- Create: `src/components/settings/OrgProfileEditor.tsx`

**Interfaces:**
- Consumes: `useOrgProfile` (Task 5); `fetchOrgVocab`, `createOrgProfile`, `updateOrgProfile`, `deleteOrgProfile`, `fetchOrgAssetSuggestions`, `OrgProfile` (Task 5).
- Produces: `<OrgProfileEditor />`, usado pela Task 9.

- [ ] **Step 1: Implementar o componente**

Criar `src/components/settings/OrgProfileEditor.tsx`:

```tsx
import { useEffect, useState } from "react";
import { Building2, Download, Loader2, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useLanguage } from "@/contexts/LanguageContext";
import { useOrgProfile } from "@/hooks/useOrgProfile";
import {
  createOrgProfile,
  deleteOrgProfile,
  fetchOrgAssetSuggestions,
  fetchOrgVocab,
  updateOrgProfile,
  type OrgProfile,
  type OrgVocab,
} from "@/services/threatApi";

const EMPTY: Partial<OrgProfile> = {
  name: "", sectors: [], regions: [], assets: [], ot: { present: false, vendors: [], protocols: [] }, actors: [],
};

// Alternar um rótulo dentro de uma lista fechada — setores e regiões só aceitam
// o vocabulário que o servidor devolve, então marcar/desmarcar é toda a edição.
const toggle = (list: string[], value: string): string[] =>
  list.includes(value) ? list.filter((item) => item !== value) : [...list, value];

export function OrgProfileEditor() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const { profiles, activeId, setActiveId, reload } = useOrgProfile();
  const [vocab, setVocab] = useState<OrgVocab>({ sectors: [], regions: [] });
  const [draft, setDraft] = useState<Partial<OrgProfile> | null>(null);
  const [saving, setSaving] = useState(false);
  const [assetInput, setAssetInput] = useState("");

  useEffect(() => { fetchOrgVocab().then(setVocab).catch(() => undefined); }, []);

  const edit = (profile: OrgProfile | null) => setDraft(profile ? { ...profile } : { ...EMPTY });

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      const saved = draft.id ? await updateOrgProfile(draft.id, draft) : await createOrgProfile(draft);
      await reload();
      // Um perfil recém-criado é quase certamente o que a pessoa quer usar.
      if (!draft.id) setActiveId(saved.id);
      setDraft(null);
      toast.success(pt ? "Perfil salvo" : "Profile saved");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao salvar");
    } finally {
      setSaving(false);
    }
  };

  const remove = async (profile: OrgProfile) => {
    try {
      await deleteOrgProfile(profile.id);
      if (activeId === profile.id) setActiveId("");
      await reload();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao remover");
    }
  };

  const importFromWatchlist = async () => {
    if (!draft) return;
    try {
      const suggestions = await fetchOrgAssetSuggestions();
      if (suggestions.length === 0) {
        toast.info(pt ? "Nenhum produto detectado no watchlist ainda" : "No products detected in the watchlist yet");
        return;
      }
      const existing = new Set((draft.assets ?? []).map((asset) => asset.product.toLowerCase()));
      const added = suggestions
        .filter((suggestion) => !existing.has(suggestion.product.toLowerCase()))
        .map((suggestion) => ({ vendor: "", product: suggestion.product }));
      setDraft({ ...draft, assets: [...(draft.assets ?? []), ...added] });
      toast.success(pt ? `${added.length} ativo(s) sugerido(s)` : `${added.length} asset(s) suggested`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao importar");
    }
  };

  const addAsset = () => {
    const product = assetInput.trim();
    if (!draft || !product) return;
    setDraft({ ...draft, assets: [...(draft.assets ?? []), { vendor: "", product }] });
    setAssetInput("");
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Building2 className="text-primary" /> {pt ? "Contexto da organização" : "Organization context"}</CardTitle>
        <CardDescription>
          {pt
            ? "O que a organização é: setor, região, ativos de software e presença de OT. As Notícias usam isso para subir e explicar o que interessa — nada é escondido por padrão."
            : "What the organization is: sector, region, software assets, and OT presence. News uses it to rank and explain what matters — nothing is hidden by default."}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {profiles.map((profile) => (
          <div key={profile.id} className="flex items-center gap-3 rounded-md border px-3 py-2">
            <input
              type="radio"
              name="active-org-profile"
              checked={activeId === profile.id}
              onChange={() => setActiveId(profile.id)}
              aria-label={pt ? `Usar ${profile.name}` : `Use ${profile.name}`}
            />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium">{profile.name}</div>
              <div className="truncate text-xs text-muted-foreground">
                {[...profile.sectors, ...profile.regions].join(" · ") || (pt ? "sem setor ou região" : "no sector or region")}
                {profile.assets.length > 0 ? ` · ${profile.assets.length} ${pt ? "ativos" : "assets"}` : ""}
                {profile.ot.present ? " · OT" : ""}
              </div>
            </div>
            <Button variant="ghost" size="sm" onClick={() => edit(profile)}>{pt ? "Editar" : "Edit"}</Button>
            <Button variant="ghost" size="sm" onClick={() => remove(profile)} aria-label={pt ? "Remover" : "Remove"}><Trash2 /></Button>
          </div>
        ))}

        {draft ? (
          <div className="flex flex-col gap-4 rounded-md border p-4">
            <div className="space-y-1.5">
              <Label htmlFor="org-name">{pt ? "Nome" : "Name"}</Label>
              <Input id="org-name" value={draft.name ?? ""} onChange={(event) => setDraft({ ...draft, name: event.target.value })} maxLength={80} />
            </div>

            <div className="space-y-1.5">
              <Label>{pt ? "Setores" : "Sectors"}</Label>
              <div className="flex flex-wrap gap-1.5">
                {vocab.sectors.map((sector) => (
                  <button
                    key={sector}
                    type="button"
                    onClick={() => setDraft({ ...draft, sectors: toggle(draft.sectors ?? [], sector) })}
                    aria-pressed={(draft.sectors ?? []).includes(sector)}
                    className={`rounded-full border px-3 py-1 text-xs transition ${(draft.sectors ?? []).includes(sector) ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
                  >
                    {sector}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>{pt ? "Regiões" : "Regions"}</Label>
              <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto">
                {vocab.regions.map((region) => (
                  <button
                    key={region}
                    type="button"
                    onClick={() => setDraft({ ...draft, regions: toggle(draft.regions ?? [], region) })}
                    aria-pressed={(draft.regions ?? []).includes(region)}
                    className={`rounded-full border px-3 py-1 text-xs transition ${(draft.regions ?? []).includes(region) ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
                  >
                    {region}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="org-asset">{pt ? "Ativos de software" : "Software assets"}</Label>
              <div className="flex gap-2">
                <Input
                  id="org-asset"
                  value={assetInput}
                  placeholder={pt ? "FortiGate, SAP, VMware ESXi…" : "FortiGate, SAP, VMware ESXi…"}
                  onChange={(event) => setAssetInput(event.target.value)}
                  onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); addAsset(); } }}
                />
                <Button variant="outline" size="sm" onClick={addAsset}><Plus /></Button>
                <Button variant="outline" size="sm" onClick={importFromWatchlist} title={pt ? "Importar do Watchlist" : "Import from Watchlist"}><Download /></Button>
              </div>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {(draft.assets ?? []).map((asset, index) => (
                  <Badge key={`${asset.product}-${index}`} variant="secondary" className="gap-1 text-[11px]">
                    {[asset.vendor, asset.product].filter(Boolean).join(" ")}
                    <button
                      type="button"
                      onClick={() => setDraft({ ...draft, assets: (draft.assets ?? []).filter((_, i) => i !== index) })}
                      aria-label={pt ? "Remover ativo" : "Remove asset"}
                    >
                      ×
                    </button>
                  </Badge>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Switch
                checked={draft.ot?.present ?? false}
                onCheckedChange={(next) => setDraft({ ...draft, ot: { ...(draft.ot ?? { vendors: [], protocols: [] }), present: next } })}
                aria-label="OT"
              />
              <span className="text-sm">{pt ? "A organização tem ambiente OT/ICS" : "The organization has an OT/ICS environment"}</span>
            </div>

            <div className="flex gap-2">
              <Button onClick={save} disabled={saving}>{saving ? <Loader2 className="animate-spin" /> : null} {pt ? "Salvar" : "Save"}</Button>
              <Button variant="ghost" onClick={() => setDraft(null)}>{pt ? "Cancelar" : "Cancel"}</Button>
            </div>
          </div>
        ) : (
          <Button variant="outline" className="self-start" onClick={() => edit(null)}><Plus /> {pt ? "Novo perfil" : "New profile"}</Button>
        )}
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 2: Verificar**

Run: `npm run typecheck && npm run lint`
Expected: sem erros.

- [ ] **Step 3: Commit**

```bash
git add src/components/settings/OrgProfileEditor.tsx
git commit -m "feat: editor de perfis de organização"
```

---

### Task 9: A aba Configurações de Monitoramento

**Files:**
- Create: `src/components/settings/MonitoringSettings.tsx`
- Modify: `src/components/settings/AdminSettings.tsx`
- Modify: `src/pages/Settings.tsx`

**Interfaces:**
- Consumes: `<OrgProfileEditor />` (Task 8); `FeedSourcesManager` (já existe, export default); `fetchExposureAssets(): Promise<ExposureAsset[]>` de `src/services/threatApi.ts:1512`, cujos ativos trazem `label` e `lastRunAt: string | null`.
- Produces: `<MonitoringSettings />`, montado na aba `monitoring` de Settings.

- [ ] **Step 1: Criar o hub**

Criar `src/components/settings/MonitoringSettings.tsx`:

```tsx
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Radar, Rss, Target } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import FeedSourcesManager from "@/components/FeedSourcesManager";
import { OrgProfileEditor } from "@/components/settings/OrgProfileEditor";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchExposureAssets } from "@/services/threatApi";

// Tudo que responde "o que este app está observando" mora aqui: o contexto que
// filtra, as fontes que coletam, e os ativos que são varridos. Os resultados
// continuam nas telas donas de cada assunto — este é o painel de configuração.
export function MonitoringSettings() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [assetCount, setAssetCount] = useState<number | null>(null);
  const [lastRun, setLastRun] = useState<string | null>(null);

  useEffect(() => {
    fetchExposureAssets()
      .then((assets) => {
        setAssetCount(assets.length);
        const runs = assets.map((asset) => asset.lastRunAt).filter(Boolean).sort();
        setLastRun(runs.length ? String(runs[runs.length - 1]) : null);
      })
      .catch(() => setAssetCount(null));
  }, []);

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="flex items-center gap-2 text-xl font-semibold"><Radar className="text-primary" /> {pt ? "Monitoramento" : "Monitoring"}</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {pt ? "O contexto que filtra, as fontes que coletam e os ativos que são varridos." : "The context that filters, the sources that collect, and the assets that get scanned."}
        </p>
      </div>

      <OrgProfileEditor />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Rss className="text-primary" /> {pt ? "Fontes de coleta" : "Collection sources"}</CardTitle>
          <CardDescription>
            {pt ? "Os feeds que alimentam as Notícias. Qualquer conta vê o catálogo; só admin edita." : "The feeds behind the news. Any account sees the catalog; only admins edit it."}
          </CardDescription>
        </CardHeader>
        <CardContent><FeedSourcesManager /></CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Target className="text-primary" /> {pt ? "Ativos monitorados" : "Monitored assets"}</CardTitle>
          <CardDescription>
            {assetCount === null
              ? (pt ? "Watchlist indisponível." : "Watchlist unavailable.")
              : pt
                ? `${assetCount} ativo(s) na watchlist${lastRun ? ` · última varredura em ${new Date(lastRun).toLocaleString("pt-BR")}` : ""}.`
                : `${assetCount} asset(s) on the watchlist${lastRun ? ` · last scan ${new Date(lastRun).toLocaleString("en-US")}` : ""}.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline"><Link to="/attack-surface?mode=monitor">{pt ? "Abrir a watchlist" : "Open the watchlist"}</Link></Button>
        </CardContent>
      </Card>
    </div>
  );
}
```

- [ ] **Step 2: Tirar o FeedSourcesManager do Admin**

Em `src/components/settings/AdminSettings.tsx`, remover a linha 5 (`import FeedSourcesManager from "@/components/FeedSourcesManager";`) e a linha 97 (`<FeedSourcesManager />`). O `<div className="flex items-start gap-3">` que o continha fica com o ícone, o título e a descrição das integrações — que é o que ele sempre deveria ter tido.

- [ ] **Step 3: Registrar a aba**

Em `src/pages/Settings.tsx`:

Trocar o tipo da linha 12:

```tsx
type SettingsSection = "general" | "monitoring" | "api-keys" | "admin";
```

Trocar a resolução da seção (linhas 30–35):

```tsx
  const requested = searchParams.get("section");
  const section: SettingsSection = requested === "api-keys"
    ? "api-keys"
    : requested === "monitoring"
      ? "monitoring"
      : requested === "admin" && auth.isAdmin
        ? "admin"
        : "general";
```

Acrescentar o gatilho depois do de "Geral" (linha 52):

```tsx
            <TabsTrigger value="monitoring"><Radar /> {tr({ pt: "Monitoramento", en: "Monitoring", es: "Monitoreo", fr: "Surveillance" })}</TabsTrigger>
```

E o conteúdo depois da linha 58:

```tsx
        <TabsContent value="monitoring" className="mt-0"><MonitoringSettings /></TabsContent>
```

Somar aos imports:

```tsx
import { Radar } from "lucide-react";
import { MonitoringSettings } from "@/components/settings/MonitoringSettings";
```

(`Radar` entra na lista de ícones já importada de `lucide-react` na linha 1.)

- [ ] **Step 4: Verificar**

Run: `npm run typecheck && npm run lint && npm run build`
Expected: sem erros.

- [ ] **Step 5: Provar na tela**

Run: `npm run server` e `npm run dev`. Abrir `/settings?section=monitoring` logado.
Expected: os três cards aparecem; criar um perfil, marcá-lo como ativo e ver o efeito em `/newsletter`; a aba Admin continua funcionando sem o card de fontes.

- [ ] **Step 6: Commit**

```bash
git add src/components/settings/MonitoringSettings.tsx src/components/settings/AdminSettings.tsx src/pages/Settings.tsx
git commit -m "feat: reunir contexto, fontes e ativos na aba Configurações de Monitoramento"
```

---

### Task 10: Vocabulário OT ampliado

**Files:**
- Modify: `server/newsCategories.js:14`
- Test: `server/test/newsCategories.test.js`

**Interfaces:**
- Consumes: nada novo.
- Produces: `categorize()` reconhece o vocabulário que Claroty e Nozomi publicam.

- [ ] **Step 1: Escrever o teste que falha**

Acrescentar a `server/test/newsCategories.test.js`:

```js
// O vocabulário das fontes OT novas: sem isso, uma pesquisa da Team82 sobre
// controlador Danfoss ou Copeland não cai no balde OT/ICS.
test('OT/ICS reconhece os fornecedores e protocolos das fontes de pesquisa OT', () => {
    const terms = [
        'Phoenix Contact', 'Copeland', 'Danfoss', 'EnOcean', 'LonTalk', 'Emerson',
        'Honeywell', 'Yokogawa', 'Mitsubishi Electric', 'Omron', 'WAGO', 'Beckhoff',
        'Moxa', 'Advantech', 'IEC 61850', 'IEC 60870', 'EtherNet/IP', 'BACnet',
        'building management system',
    ];
    for (const term of terms) {
        assert.ok(
            categorize(item({ title: `Vulnerabilities found in ${term} controllers` })).categories.includes('OT/ICS'),
            term,
        );
    }
});
```

- [ ] **Step 2: Rodar e ver falhar**

Run: `npm run test:server -- --test-name-pattern="fornecedores e protocolos"`
Expected: FAIL no primeiro termo, `Phoenix Contact`.

- [ ] **Step 3: Ampliar a regex**

Em `server/newsCategories.js`, trocar a linha 14 por:

```js
const OT_ICS = /\b(?:ot\/ics|ics\/ot|\bics\b|scada|\bplc\b|\bhmi\b|modbus|opc ua|profinet|dnp3|purdue|safety instrumented|siemens s7|simatic|rockwell|allen[- ]bradley|schneider electric|codesys|phoenix contact|copeland|danfoss|enocean|lontalk|emerson|honeywell|yokogawa|mitsubishi electric|omron|wago|beckhoff|moxa|advantech|iec ?6(?:1850|0870)|ethernet\/ip|bacnet|building management system|\bbms\b)\b/i;
```

Os termos novos são inequívocos em prosa CTI — todos são marca de fabricante industrial, norma ou protocolo —, então entram na mesma alternância, sem exigir contexto vizinho como fazem os aliases de ator em `actorMatch.js`.

- [ ] **Step 4: Rodar e ver passar**

Run: `npm run test:server`
Expected: PASS, incluindo os testes antigos de `newsCategories`.

- [ ] **Step 5: Commit**

```bash
git add server/newsCategories.js server/test/newsCategories.test.js
git commit -m "feat: reconhecer o vocabulário OT das fontes de pesquisa industrial"
```

---

### Task 11: RSS do portal de segurança da Nozomi

**Files:**
- Modify: `server/ctiIntel.js:398-441`

**Interfaces:**
- Consumes: `CTI_FEEDS`, já lido por `effectiveFeeds()` em `server/index.js`.
- Produces: nada novo.

- [ ] **Step 1: Confirmar que o feed responde**

Run: `curl -sI -A "Mozilla/5.0" https://security.nozominetworks.com/rss.xml | head -3`
Expected: `HTTP/2 200` e `content-type: application/xml`.

- [ ] **Step 2: Somar ao catálogo**

Em `server/ctiIntel.js`, na Layer 1 (junto dos outros PSIRT, depois da linha do Palo Alto PSIRT):

```js
    { url: 'https://security.nozominetworks.com/rss.xml', source: 'Nozomi Networks PSIRT', layer: 1, weight_boost: 20 },
```

- [ ] **Step 3: Verificar**

Run: `node --check server/ctiIntel.js && npm run test:server`
Expected: sem erro; testes verdes.

- [ ] **Step 4: Commit**

```bash
git add server/ctiIntel.js
git commit -m "feat: somar o portal de segurança da Nozomi ao catálogo de feeds"
```

---

### Task 12: Raspador das fontes sem RSS

**Files:**
- Create: `server/scrapeFeeds.js`
- Create: `server/test/fixtures/claroty-research.html`, `server/test/fixtures/claroty-white-papers.html`, `server/test/fixtures/nozomi-blog.html`
- Test: `server/test/scrapeFeeds.test.js`

**Interfaces:**
- Consumes: `cheerio` (já em `server/package.json`).
- Produces: `SCRAPE_SOURCES`, `parseListing(html, source)` → `[{title, link, source, layer, weight_boost}]`, `publishedTime(html)` → ISO string ou `null`, `collectScraped({sources, fetchText, seen, now, maxNew})` → `{items, seen}`.

- [ ] **Step 1: Baixar os fixtures**

```bash
mkdir -p server/test/fixtures
curl -s -L -A "Mozilla/5.0" "https://claroty.com/team82/research?team82_resources_tab=team82_research" -o server/test/fixtures/claroty-research.html
curl -s -L -A "Mozilla/5.0" "https://claroty.com/team82/research?team82_resources_tab=team82_white_papers" -o server/test/fixtures/claroty-white-papers.html
curl -s -L -A "Mozilla/5.0" "https://www.nozominetworks.com/blog" -o server/test/fixtures/nozomi-blog.html
```

Conferir que os três arquivos têm conteúdo: `wc -c server/test/fixtures/*.html` deve mostrar dezenas ou centenas de KB.

- [ ] **Step 2: Escrever o teste que falha**

Criar `server/test/scrapeFeeds.test.js`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCRAPE_SOURCES, collectScraped, parseListing, publishedTime } from '../scrapeFeeds.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => fs.readFileSync(path.join(here, 'fixtures', name), 'utf8');
const sourceNamed = (name) => SCRAPE_SOURCES.find((source) => source.source === name);

test('o catálogo tem as três páginas, com as duas da Claroty datadas', () => {
    assert.equal(SCRAPE_SOURCES.length, 3);
    assert.equal(sourceNamed('Claroty Team82').datedItems, true);
    assert.equal(sourceNamed('Claroty Team82 White Papers').datedItems, true);
    assert.equal(sourceNamed('Nozomi Networks Blog').datedItems, false);
});

test('parseListing extrai título e link absoluto da Claroty', () => {
    const items = parseListing(fixture('claroty-research.html'), sourceNamed('Claroty Team82'));
    assert.ok(items.length >= 5, `esperava vários itens, veio ${items.length}`);
    for (const item of items) {
        assert.ok(item.link.startsWith('https://claroty.com/team82/research/'), item.link);
        assert.ok(item.title.length > 10, item.title);
        assert.equal(item.source, 'Claroty Team82');
        assert.equal(item.layer, 3);
    }
    assert.equal(new Set(items.map((item) => item.link)).size, items.length, 'sem link repetido');
});

// As duas abas moram na mesma URL base e diferem só pela query — se o seletor
// pegasse a página inteira, elas trariam a mesma coisa.
test('as duas abas da Claroty trazem conjuntos diferentes', () => {
    const research = parseListing(fixture('claroty-research.html'), sourceNamed('Claroty Team82'));
    const papers = parseListing(fixture('claroty-white-papers.html'), sourceNamed('Claroty Team82 White Papers'));
    assert.ok(papers.every((item) => item.link.includes('/white-papers/')));
    assert.equal(research.filter((item) => item.link.includes('/white-papers/')).length, 0);
});

test('parseListing extrai o blog da Nozomi', () => {
    const items = parseListing(fixture('nozomi-blog.html'), sourceNamed('Nozomi Networks Blog'));
    assert.ok(items.length >= 20, `esperava vários posts, veio ${items.length}`);
    for (const item of items) assert.ok(item.link.startsWith('https://www.nozominetworks.com/blog/'), item.link);
});

test('publishedTime lê a meta do post', () => {
    assert.equal(
        publishedTime('<meta property="article:published_time" content="2026-06-09T16:00:00+00:00">'),
        '2026-06-09T16:00:00.000Z',
    );
    assert.equal(publishedTime('<html><body>sem data</body></html>'), null);
});

const listingHtml = (slugs) =>
    `<main>${slugs.map((slug) => `<a href="/blog/${slug}"><h2>Post ${slug}</h2></a>`).join('')}</main>`;

const nozomi = () => ({ ...sourceNamed('Nozomi Networks Blog') });
const now = new Date('2026-08-17T12:00:00.000Z');

// Uma fonte sem data confiável não pode ser retroativa sem inventar quando as
// coisas aconteceram — então a primeira rodada só semeia.
test('partida a frio semeia em silêncio', async () => {
    const result = await collectScraped({
        sources: [nozomi()],
        fetchText: async () => listingHtml(['a', 'b', 'c']),
        seen: {},
        now,
        maxNew: 10,
    });
    assert.deepEqual(result.items, []);
    assert.equal(Object.keys(result.seen).length, 3);
});

test('a segunda rodada emite só o que apareceu depois', async () => {
    const first = await collectScraped({ sources: [nozomi()], fetchText: async () => listingHtml(['a', 'b']), seen: {}, now, maxNew: 10 });
    const later = new Date('2026-08-18T12:00:00.000Z');
    const second = await collectScraped({
        sources: [nozomi()],
        fetchText: async () => listingHtml(['a', 'b', 'c']),
        seen: first.seen,
        now: later,
        maxNew: 10,
    });
    assert.deepEqual(second.items.map((item) => item.link), ['https://www.nozominetworks.com/blog/c']);
    assert.equal(second.items[0].pubDate, later.toISOString());
});

test('maxNew limita quantos novos entram por rodada', async () => {
    const first = await collectScraped({ sources: [nozomi()], fetchText: async () => listingHtml(['a']), seen: {}, now, maxNew: 10 });
    const second = await collectScraped({
        sources: [nozomi()],
        fetchText: async () => listingHtml(['a', 'b', 'c', 'd']),
        seen: first.seen,
        now,
        maxNew: 2,
    });
    assert.equal(second.items.length, 2);
});

// Fonte datada emite já na primeira rodada, porque a data é real e não first-seen.
test('fonte datada busca a data do post e emite na partida a frio', async () => {
    const source = { ...sourceNamed('Claroty Team82') };
    const result = await collectScraped({
        sources: [source],
        fetchText: async (url) => (
            url.includes('?')
                ? '<main><a href="/team82/research/algo"><h2>Um estudo</h2></a></main>'
                : '<meta property="article:published_time" content="2026-06-09T16:00:00+00:00">'
        ),
        seen: {},
        now,
        maxNew: 10,
    });
    assert.equal(result.items.length, 1);
    assert.equal(result.items[0].pubDate, '2026-06-09T16:00:00.000Z');
});

test('fonte que quebra não derruba as outras', async () => {
    const result = await collectScraped({
        sources: [nozomi(), { ...sourceNamed('Claroty Team82') }],
        fetchText: async (url) => {
            if (url.includes('claroty')) throw new Error('502');
            return listingHtml(['a']);
        },
        seen: { 'https://www.nozominetworks.com/blog/a': '2026-08-01T00:00:00.000Z' },
        now,
        maxNew: 10,
    });
    assert.deepEqual(result.items, [], 'a Nozomi já conhecia o link, a Claroty falhou');
    assert.ok(result.errors.some((error) => error.source === 'Claroty Team82'));
});
```

- [ ] **Step 3: Rodar e ver falhar**

Run: `npm run test:server`
Expected: FAIL com `Cannot find module '.../server/scrapeFeeds.js'`.

- [ ] **Step 4: Implementar**

Criar `server/scrapeFeeds.js`:

```js
// Fontes de pesquisa que não publicam RSS.
//
// Claroty Team82 e o blog da Nozomi são as duas melhores fontes de pesquisa OT
// abertas e nenhuma das duas tem feed. As páginas são renderizadas no servidor,
// então uma raspagem de listagem basta — e o retorno tem a mesma forma que
// parseFeed() produz, para score, atores, categorias e agrupamento de histórias
// virem de graça, sem tocar em refreshNewsletterFeed.
import * as cheerio from 'cheerio';

export const SCRAPE_SOURCES = [
    {
        source: 'Claroty Team82',
        url: 'https://claroty.com/team82/research?team82_resources_tab=team82_research',
        origin: 'https://claroty.com',
        linkPattern: /^\/team82\/research\/(?!white-papers\/)/,
        layer: 3,
        weight_boost: 15,
        // O post traz article:published_time, então a data é a de verdade.
        datedItems: true,
    },
    {
        source: 'Claroty Team82 White Papers',
        url: 'https://claroty.com/team82/research?team82_resources_tab=team82_white_papers',
        origin: 'https://claroty.com',
        linkPattern: /^\/team82\/research\/white-papers\//,
        layer: 3,
        weight_boost: 15,
        datedItems: true,
    },
    {
        source: 'Nozomi Networks Blog',
        url: 'https://www.nozominetworks.com/blog',
        origin: 'https://www.nozominetworks.com',
        linkPattern: /^\/blog\/[^/]+$/,
        layer: 3,
        weight_boost: 12,
        // O datePublished do JSON-LD é inconfiável — um post de dezembro/2024
        // chega como "Aug 12, 2026". Melhor datar pela primeira aparição do que
        // publicar uma data errada.
        datedItems: false,
    },
];

const clean = (value) => String(value || '').replace(/\s+/g, ' ').trim();

/** Itens da listagem, na mesma forma que parseFeed() devolve. */
export function parseListing(html, source) {
    const items = [];
    const seen = new Set();
    try {
        const $ = cheerio.load(html);
        $('a[href]').each((_, element) => {
            const href = $(element).attr('href') || '';
            let url;
            try { url = new URL(href, source.origin); } catch { return; }
            if (url.origin !== source.origin) return;
            if (!source.linkPattern.test(url.pathname)) return;

            const title = clean($(element).find('h1, h2, h3').first().text()) || clean($(element).text());
            if (title.length < 10) return;

            url.hash = '';
            url.search = '';
            const link = url.toString();
            if (seen.has(link)) return;
            seen.add(link);
            items.push({ title, link, source: source.source, layer: source.layer, weight_boost: source.weight_boost, description: '' });
        });
    } catch { /* HTML impossível de ler: nenhum item, nenhum crash */ }
    return items;
}

/** Data de publicação declarada pela própria página, ou null. */
export function publishedTime(html) {
    const match = String(html || '').match(/<meta[^>]+property=["']article:published_time["'][^>]+content=["']([^"']+)["']/i);
    if (!match) return null;
    const parsed = new Date(match[1]);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

/**
 * Raspa cada fonte e devolve só o que ainda não tinha sido visto.
 *
 * `seen` é o mapa persistido `{link: pubDate}`; a função não escreve em disco —
 * devolve o mapa novo e quem chamou decide gravar. `fetchText(url)` devolve o
 * HTML como string. Uma fonte que estoura entra em `errors` e não impede as outras.
 */
export async function collectScraped({ sources, fetchText, seen = {}, now = new Date(), maxNew = 10 }) {
    const nextSeen = { ...seen };
    const items = [];
    const errors = [];

    for (const source of sources) {
        try {
            const listing = parseListing(await fetchText(source.url), source);
            // Uma fonte sem nenhum link conhecido é partida a frio: sem data real
            // não dá para publicar o histórico sem inventar quando aconteceu.
            const coldStart = !listing.some((item) => nextSeen[item.link]);
            let taken = 0;

            for (const item of listing) {
                if (nextSeen[item.link]) continue;
                if (taken >= maxNew) {
                    // Além do teto, registra sem emitir: na próxima rodada estes
                    // deixam de ser "novos" e o feed não leva uma enxurrada.
                    nextSeen[item.link] = now.toISOString();
                    continue;
                }
                taken += 1;

                let pubDate = now.toISOString();
                if (source.datedItems) {
                    try {
                        pubDate = publishedTime(await fetchText(item.link)) || pubDate;
                    } catch { /* sem a data real, vale a primeira aparição */ }
                }
                nextSeen[item.link] = pubDate;
                if (!coldStart || source.datedItems) items.push({ ...item, pubDate });
            }
        } catch (error) {
            errors.push({ source: source.source, message: error.message });
        }
    }

    return { items, seen: nextSeen, errors };
}
```

- [ ] **Step 5: Rodar e ver passar**

Run: `npm run test:server`
Expected: PASS. Se algum teste de fixture falhar por mudança de layout no site, ajustar o seletor em `parseListing` — **não** o teste.

- [ ] **Step 6: Commit**

```bash
git add server/scrapeFeeds.js server/test/scrapeFeeds.test.js server/test/fixtures/
git commit -m "feat: raspador das fontes de pesquisa OT sem RSS"
```

---

### Task 13: Ligar o raspador ao refresh do feed

**Files:**
- Modify: `server/index.js:1661-1757`

**Interfaces:**
- Consumes: `SCRAPE_SOURCES`, `collectScraped` (Task 12); `axios`, `writeJsonAtomic`, `feedHealth`, `scoreArticle` — já em `server/index.js`.
- Produces: itens raspados entram no `unifiedFeed` como qualquer item de RSS.

- [ ] **Step 1: Importar e preparar o estado**

Nos imports de `server/index.js`:

```js
import { SCRAPE_SOURCES, collectScraped } from './scrapeFeeds.js';
```

Junto dos outros caminhos de store (perto da linha 124):

```js
// Data de primeira aparição das fontes raspadas. Sem isto, cada refresh de 10
// minutos recarimbaria todo post com a hora atual.
const SCRAPE_SEEN_PATH = path.join(__dirname, '.scrape-seen.json');
let scrapeSeen = {};
try { scrapeSeen = JSON.parse(fs.readFileSync(SCRAPE_SEEN_PATH, 'utf8')) || {}; } catch { scrapeSeen = {}; }
```

- [ ] **Step 2: Raspar dentro do refresh**

Em `refreshNewsletterFeed()`, logo depois do bloco que monta `successfulFeeds` (linha ~1692), antes da de-duplicação por URL:

```js
        // Fontes sem RSS. Falha aqui não pode levar o feed junto: no pior caso
        // as notícias do dia saem sem a pesquisa OT.
        let scraped = [];
        try {
            const result = await collectScraped({
                // Respeita o mesmo interruptor dos feeds RSS: se a fonte aparece
                // desligável na tela, desligar precisa desligar de verdade.
                sources: SCRAPE_SOURCES.filter((source) => !feedOverrides.disabled.includes(source.url)),
                fetchText: async (url) => (await axios.get(url, {
                    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36' },
                    timeout: 8000,
                })).data,
                seen: scrapeSeen,
                now: new Date(),
                maxNew: 10,
            });
            scraped = result.items.map((item) => ({
                ...item,
                ...scoreArticle(`${item.title} ${item.description}`, item.weight_boost),
            }));
            // Poda pelo fim mais antigo: o mapa não pode crescer sem limite.
            const entries = Object.entries(result.seen).sort((a, b) => String(b[1]).localeCompare(String(a[1]))).slice(0, 2000);
            scrapeSeen = Object.fromEntries(entries);
            writeJsonAtomic(SCRAPE_SEEN_PATH, scrapeSeen);
            for (const source of SCRAPE_SOURCES) {
                const failure = result.errors.find((error) => error.source === source.source);
                feedHealth.set(source.url, {
                    ok: !failure,
                    count: result.items.filter((item) => item.source === source.source).length,
                    error: failure ? failure.message : null,
                    at: new Date().toISOString(),
                });
            }
        } catch (error) {
            console.error('scraped sources failed:', error.message);
        }
```

E trocar o laço de de-duplicação (linha ~1697) para incluir os raspados:

```js
        for (const item of [...successfulFeeds, ...scraped]) {
```

- [ ] **Step 3: Mostrar as fontes raspadas no catálogo**

Sem isto, um raspador que quebra devolve zero itens e ninguém percebe — a saúde já é gravada em `feedHealth`, só falta chegar à tela. `feedListForClient()` é a costura de exibição; `catalogFeeds()` e `effectiveFeeds()` ficam intocados, para o coletor de RSS não tentar buscar uma página HTML como se fosse feed.

Em `server/index.js`, trocar o corpo de `feedListForClient()` (linha 1939):

```js
function feedListForClient() {
    const withHealth = (feed) => {
        const h = feedHealth.get(feed.url);
        return {
            url: feed.url, source: feed.source, layer: feed.layer, weight_boost: feed.weight_boost,
            builtin: feed.builtin, enabled: feed.enabled,
            health: h ? { ok: h.ok, count: h.count, error: h.error, at: h.at } : null,
        };
    };
    const scraped = SCRAPE_SOURCES.map((source) => withHealth({
        ...source, builtin: true, enabled: !feedOverrides.disabled.includes(source.url),
    }));
    return [...catalogFeeds().map(withHealth), ...scraped];
}
```

- [ ] **Step 4: Verificar**

Run: `node --check server/index.js && npm run test:server`
Expected: sem erro de sintaxe; testes verdes.

- [ ] **Step 5: Provar de ponta a ponta**

Run: `cd server && node index.js`. Esperar o primeiro refresh e conferir:

```bash
node -e "const s=require('./server/.scrape-seen.json'); console.log(Object.keys(s).length, 'links semeados')"
curl -s localhost:3001/api/newsletter | node -e "let b='';process.stdin.on('data',d=>b+=d).on('end',()=>{const f=JSON.parse(b).filter(i=>/Claroty|Nozomi/.test(i.source));console.log(f.length,'itens das fontes novas');console.log(f.slice(0,3).map(i=>`${i.source} · ${i.pubDate} · ${i.title}`).join('\n'))})"
```

Expected: `.scrape-seen.json` com centenas de links; itens da Claroty com data real já na primeira rodada; blog da Nozomi sem itens na primeira rodada (semeado em silêncio), o que é o comportamento desenhado. Ajustar a porta se o log do servidor mostrar outra.

Conferir também que as três fontes novas aparecem em `/settings?section=monitoring`, no card de fontes, com a saúde do último refresh.

- [ ] **Step 6: Commit**

```bash
git add server/index.js
git commit -m "feat: coletar as fontes de pesquisa OT no refresh do feed"
```

---

## Verificação final

- [ ] `npm run test:server` — todos verdes
- [ ] `npm run test:unit` — todos verdes
- [ ] `npm run ci` (lint + typecheck + build) — sem erros
- [ ] `.gitignore` já cobre `server/.*.json`? Conferir com `git status` que `.org-profiles.json` e `.scrape-seen.json` **não** aparecem como não rastreados; se aparecerem, acrescentá-los ao `.gitignore` junto dos outros stores.
- [ ] Fluxo completo à mão: criar perfil em `/settings?section=monitoring` → marcar como ativo → abrir `/newsletter` → ver o chip, a ordenação e o filtro → voltar a "Sem contexto" e confirmar que a tela é a de antes.
