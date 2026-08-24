import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeIntoStories, rareTerms, STORY_RETENTION_DAYS } from '../newsStories.js';

const NOW = new Date('2026-08-12T12:00:00Z');
const daysBefore = (n) => new Date(NOW.getTime() - n * 86400000).toISOString();

const item = (over = {}) => ({
    title: 'Untitled', description: '', link: `https://x.example/${Math.random()}`,
    source: 'Feed', pubDate: NOW.toISOString(), score: 50, severity: 'High',
    cves: [], actors: [], newsCategories: [], primaryCategory: null, ...over,
});

// Pins the /api/newsletter compatibility promise at the one seam a pure module
// can see: item.categories is scoreArticle's CTI scoring labels and must never
// feed story-building — only item.newsCategories (the navigation buckets) may.
// If the server's enrichment loop regressed to writing navigation categories
// back onto item.categories (the original bug), this item would arrive with no
// item.newsCategories, and the story would come back with categories: [] even
// though categories: [...] is sitting right there — that's the failure this
// guards against.
test('a história lê newsCategories, nunca as categorias CTI de scoreArticle', () => {
    const stories = mergeIntoStories([], [
        item({
            title: 'Cl0p exploits Oracle EBS zero-day',
            link: 'https://a.example/1',
            // CTI scoring labels from scoreArticle — must survive untouched on the
            // item and must NOT leak into the story's navigation categories.
            categories: ['Active Exploitation', 'Malware/Ransomware', 'Critical Vendor'],
            newsCategories: ['Ransomware', 'Vulnerabilities'],
        }),
    ], NOW);
    assert.equal(stories.length, 1);
    assert.deepEqual(stories[0].categories, ['Ransomware', 'Vulnerabilities'], 'story categories come from newsCategories');
    assert.ok(!stories[0].categories.includes('Active Exploitation'), 'CTI scoring labels never reach the story');
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

test('primaryCategory segue a precedência, não a ordem de chegada', () => {
    // First item categorised as Microsoft (last in precedence),
    // second categorised as Ransomware (first in precedence).
    // The merged story should have primaryCategory='Ransomware' and
    // categories in precedence order.
    const stories = mergeIntoStories([], [
        item({ title: 'Microsoft Exchange vulnerability discovered', link: 'https://a.example/1', cves: ['CVE-1'], newsCategories: ['Microsoft'] }),
        item({ title: 'Ransomware group exploits Exchange', link: 'https://b.example/2', cves: ['CVE-1'], newsCategories: ['Ransomware'] }),
    ], NOW);
    assert.equal(stories.length, 1);
    assert.equal(stories[0].primaryCategory, 'Ransomware', 'primaryCategory deve seguir precedência');
    assert.deepEqual(stories[0].categories, ['Ransomware', 'Microsoft'], 'categories deve estar em ordem de precedência');
});

test('recompute de signals a cada iteração: candidate herda raridade de A e casa com B', () => {
    // Story A: CVE-1, title "Oracle database" → {database, oracle}
    // Story B: title "Oracle scandal" → {oracle, scandal}
    // A vs B: Jaccard({database,oracle}, {oracle,scandal}) = 1/3 ≈ 0.33 < 0.5, separate
    // Candidate: CVE-1, title "Scandal" → {scandal} only (1 rare term)
    // Candidate vs B (before absorb): size < MIN_RARE_FOR_JACCARD, returns 0, no match
    // Candidate matches A via CVE-1, merges
    // After absorbing A: Candidate has both titles' rare terms: {database, oracle, scandal}
    // Candidate vs B: Jaccard({database,oracle,scandal}, {oracle,scandal}) = 2/3 ≈ 0.67 >= 0.5
    const seed = mergeIntoStories([], [
        item({ title: 'Oracle database', link: 'https://a.example/1', cves: ['CVE-1'], pubDate: daysBefore(1) }),
        item({ title: 'Oracle scandal', link: 'https://b.example/2', pubDate: daysBefore(1) }),
    ], NOW);
    assert.equal(seed.length, 2, 'A and B remain separate: Jaccard = 0.33');

    // Candidate: CVE-1, single rare term {scandal}
    // Matches A via CVE-1, inherits A's {database, oracle}
    // After absorbing A, recomputed signals allow match with B
    const bridged = mergeIntoStories(seed, [item({
        title: 'Scandal', link: 'https://c.example/3',
        cves: ['CVE-1'],
    })], NOW);
    assert.equal(bridged.length, 1, 'recompute enables candidate to match B after inheriting A rareness');
    assert.equal(bridged[0].sources.length, 3, 'merged story has all three sources');
});

// ─── Séries recorrentes e apanhados ────────────────────────────────────────
// Cenário real: uma semana de feed virou UM card com oito matérias, misturando
// o Windows IKE com o MLflow com os boletins diários da CISA.

const KEV_DAY = (day, n, cves) => item({
    source: 'CISA Advisories',
    title: `CISA Adds ${n} Known Exploited Vulnerabilities to Catalog`,
    link: `https://cisa.example/kev-${day}`,
    pubDate: `2026-08-${day}T12:00:00Z`,
    cves,
});

test('a mesma manchete do mesmo veículo em outro dia é outra edição, não a mesma notícia', () => {
    // "CISA Adds One Known Exploited Vulnerability to Catalog" sai quase todo
    // dia: os termos raros são idênticos e o jaccard dá 1.0.
    const stories = mergeIntoStories([], [
        KEV_DAY('17', 'One', ['CVE-2026-1']),
        KEV_DAY('19', 'One', ['CVE-2026-2']),
    ], new Date('2026-08-21T12:00:00Z'));

    assert.equal(stories.length, 2, 'duas edições da série viraram um card só');
});

test('mesma manchete no mesmo dia continua sendo republicação', () => {
    const stories = mergeIntoStories([], [
        KEV_DAY('17', 'One', ['CVE-2026-1']),
        { ...KEV_DAY('17', 'One', ['CVE-2026-1']), link: 'https://cisa.example/kev-17-mirror' },
    ], new Date('2026-08-21T12:00:00Z'));

    assert.equal(stories.length, 1);
    assert.equal(stories[0].sources.length, 2);
});

test('apanhado de CVEs não cola matérias sobre falhas diferentes', () => {
    // O boletim de 20/08 lista quatro CVEs. Sem o corte, a matéria do MLflow e a
    // do Windows IKE entram nele — e, como o absorve recomputa os sinais a cada
    // rodada, passam a ser a mesma notícia uma da outra.
    const stories = mergeIntoStories([], [
        KEV_DAY('20', 'Four', ['CVE-2026-10', 'CVE-2026-11', 'CVE-2026-12', 'CVE-2026-13']),
        item({
            source: 'CISO Advisor BR', title: 'CISA alerta para exploração ativa de falha crítica no MLflow',
            link: 'https://ciso.example/mlflow', pubDate: '2026-08-20T15:00:00Z', cves: ['CVE-2026-10'],
        }),
        item({
            source: 'CISO Advisor BR', title: 'CISA alerta para exploração ativa de falha crítica no Windows IKE',
            link: 'https://ciso.example/ike', pubDate: '2026-08-20T16:00:00Z', cves: ['CVE-2026-11'],
        }),
    ], new Date('2026-08-21T12:00:00Z'));

    const titles = stories.flatMap((s) => s.sources.map((src) => src.title));
    const mlflow = stories.find((s) => s.sources.some((src) => src.title.includes('MLflow')));
    const ike = stories.find((s) => s.sources.some((src) => src.title.includes('Windows IKE')));

    assert.equal(titles.length, 3, 'nenhuma matéria pode sumir');
    assert.notEqual(mlflow.id, ike.id, 'MLflow e Windows IKE viraram a mesma notícia pelo apanhado');
});

test('matérias sobre a MESMA falha continuam agrupando pelo CVE', () => {
    // O corte é sobre apanhado, não sobre a regra do CVE: dois veículos falando
    // do mesmo CVE seguem sendo a mesma cobertura.
    const stories = mergeIntoStories([], [
        item({
            source: 'CISO Advisor BR', title: 'Falha do MLflow já está sendo atacada',
            link: 'https://ciso.example/mlflow-2', pubDate: '2026-08-20T18:00:00Z', cves: ['CVE-2026-10'],
        }),
        item({
            source: 'BleepingComputer', title: 'MLflow deserialization flaw under active exploitation',
            link: 'https://bleeping.example/mlflow', pubDate: '2026-08-20T19:00:00Z', cves: ['CVE-2026-10'],
        }),
    ], new Date('2026-08-21T12:00:00Z'));

    assert.equal(stories.length, 1);
    assert.equal(stories[0].sources.length, 2);
});

test('a semana inteira de boletins não desaba num card', () => {
    const stories = mergeIntoStories([], [
        KEV_DAY('17', 'One', ['CVE-2026-1']),
        KEV_DAY('18', 'Four', ['CVE-2026-2', 'CVE-2026-3', 'CVE-2026-4', 'CVE-2026-5']),
        KEV_DAY('19', 'One', ['CVE-2026-6']),
        KEV_DAY('20', 'Two', ['CVE-2026-7', 'CVE-2026-8']),
        item({
            source: 'CISO Advisor BR', title: 'CISA confirma exploração de falha do Windows por ransomware',
            link: 'https://ciso.example/win', pubDate: '2026-08-18T14:00:00Z', cves: ['CVE-2026-2'],
        }),
        item({
            source: 'CISO Advisor BR', title: 'CISA alerta para exploração ativa de falha crítica no Windows IKE',
            link: 'https://ciso.example/ike2', pubDate: '2026-08-19T14:00:00Z', cves: ['CVE-2026-6'],
        }),
    ], new Date('2026-08-21T12:00:00Z'));

    const biggest = Math.max(...stories.map((s) => s.sources.length));
    assert.ok(stories.length >= 4, `esperava vários cards, veio ${stories.length}`);
    assert.ok(biggest <= 2, `um card engoliu ${biggest} matérias`);
});

// ─── Medido contra o feed real (1209 itens, 35 fontes) ──────────────────────
// Os quatro casos abaixo saíram de rodar o merge no feed de verdade: cada um é
// um card errado que apareceu na tela, ou uma cobertura óbvia que não agrupou.

test('apanhado com poucos CVEs também não empresta CVE', () => {
    // "CISA Adds Three ..." tem exatamente três CVEs, passa no cap, e virava o
    // eixo de um card com Cisco ASA + Lazarus + KEV, assuntos sem relação.
    const stories = mergeIntoStories([], [
        KEV_DAY('11', 'Three', ['CVE-2026-20349', 'CVE-2026-68820', 'CVE-2026-72898']),
        item({
            source: 'Cisco PSIRT', title: 'Cisco Secure Firewall Adaptive Security Appliance VPN Vulnerability',
            link: 'https://cisco.example/asa', pubDate: '2026-08-11T15:00:00Z', cves: ['CVE-2026-20349'],
        }),
        item({
            source: 'CISO Advisor BR', title: 'Grupo Lazarus explora zero-day do Windows contra empresas de defesa',
            link: 'https://ciso.example/lazarus', pubDate: '2026-08-11T16:00:00Z', cves: ['CVE-2026-68820'],
        }),
    ], new Date('2026-08-12T12:00:00Z'));

    assert.equal(stories.length, 3, 'o apanhado colou Cisco e Lazarus na mesma história');
});

test('manchete parecida do mesmo veículo em outro dia é a próxima edição', () => {
    // Onze releases do Chrome viraram um card só: "Chrome Beta for Android
    // Update" e "Chrome for Android Update" não têm o mesmo esqueleto, então o
    // veto de série não pegava, e o jaccard casava.
    const chrome = (day, title) => item({
        source: 'Chrome Releases', title, link: `https://chrome.example/${day}-${title}`,
        pubDate: `2026-08-${day}T12:00:00Z`,
    });
    const outrosDias = mergeIntoStories([], [
        chrome('06', 'Chrome Beta for Android Update'),
        chrome('11', 'Chrome for Android Update'),
    ], new Date('2026-08-12T12:00:00Z'));
    assert.equal(outrosDias.length, 2);

    const mesmoDia = mergeIntoStories([], [
        chrome('11', 'Chrome Beta for Android Update'),
        chrome('11', 'Chrome for Android Update'),
    ], new Date('2026-08-12T12:00:00Z'));
    assert.equal(mesmoDia.length, 1, 'no mesmo dia é o mesmo lote de release');
});

test('classe da falha não é assunto: produtos diferentes não viram uma história', () => {
    const stories = mergeIntoStories([], [
        item({
            source: 'Zero Day Initiative', title: 'ZDI-26-552: OriginLab Origin Viewer OPJ File Parsing Out-Of-Bounds Write',
            link: 'https://zdi.example/552', cves: ['CVE-2026-18293'],
        }),
        item({
            source: 'Zero Day Initiative', title: 'ZDI-26-566: BlackBerry QNX File Parsing Out-Of-Bounds Write Remote Code Execution',
            link: 'https://zdi.example/566', cves: ['CVE-2026-40272'],
        }),
    ], NOW);

    assert.equal(stories.length, 2);
});

test('dois veículos cobrindo a mesma campanha agrupam mesmo sem CVE', () => {
    // É a correlação que o limiar de 0.5 perdia: cada redação escolhe as
    // próprias palavras, e só o nome da campanha e a região sobrevivem.
    const stories = mergeIntoStories([], [
        item({
            source: 'The Hacker News', title: 'SilkParasite Espionage Campaign Targets Central Asian Governments with RATs',
            link: 'https://thn.example/silkparasite',
        }),
        item({
            source: 'Dark Reading', title: 'SilkParasite Threatens Central Asian Orgs With Flurry of RATs',
            link: 'https://dr.example/silkparasite',
        }),
    ], NOW);

    assert.equal(stories.length, 1, 'a mesma campanha em dois veículos continuou em cards separados');
    assert.equal(stories[0].sources.length, 2);
});
