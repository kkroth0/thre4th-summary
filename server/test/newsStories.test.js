import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeIntoStories, rareTerms, STORY_RETENTION_DAYS } from '../newsStories.js';

const NOW = new Date('2026-08-12T12:00:00Z');
const daysBefore = (n) => new Date(NOW.getTime() - n * 86400000).toISOString();

const item = (over = {}) => ({
    title: 'Untitled', description: '', link: `https://x.example/${Math.random()}`,
    source: 'Feed', pubDate: NOW.toISOString(), score: 50, severity: 'High',
    cves: [], actors: [], malware: [], campaigns: [], ttpIds: [], newsCategories: [], primaryCategory: null, ...over,
});

test('CVEs distintas vetam a semelhança do título e a técnica comum, mas uma campanha pode unir incidente multi-CVE', () => {
    const pair = [
        item({ title: 'Citrix NetScaler emergency patch', link: 'https://a.example/citrix', cves: ['CVE-2026-107406'], ttpIds: ['T1190'] }),
        item({ title: 'Citrix NetScaler emergency patch', link: 'https://b.example/citrix', cves: ['CVE-2026-88771'], ttpIds: ['T1190'] }),
    ];
    assert.equal(mergeIntoStories([], pair, NOW).length, 2);
    const campaign = { id: 'operation-net', name: 'Operation Net', matched: 'Operation Net' };
    assert.equal(mergeIntoStories([], pair.map((article) => ({ ...article, campaigns: [campaign] })), NOW).length, 1);
});

test('coberturas históricas do mesmo evento agrupam também no primeiro lote', () => {
    const stories = mergeIntoStories([], [
        item({ link: 'https://a.example/old', pubDate: daysBefore(25), cves: ['CVE-2026-12345'] }),
        item({ link: 'https://b.example/old', pubDate: daysBefore(24), cves: ['CVE-2026-12345'] }),
    ], NOW);
    assert.equal(stories.length, 1, 'a janela compara publicações entre si, não apenas com hoje');
});

test('atualização da mesma URL mantém o ID e atualiza evidências sem duplicar a publicação', () => {
    const original = item({ link: 'https://a.example/Post?utm_source=rss', cves: [], score: 20 });
    const first = mergeIntoStories([], [original], NOW);
    const updated = mergeIntoStories(first, [item({ ...original, link: 'https://a.example/Post', cves: ['CVE-2026-12345'], score: 80, actors: [{ id: 'a1', name: 'APT29' }] })], NOW);
    assert.equal(updated[0].id, first[0].id);
    assert.equal(updated[0].sources.length, 1);
    assert.deepEqual(updated[0].cves, ['CVE-2026-12345']);
    assert.equal(updated[0].score, 80);
    assert.equal(updated[0].sources[0].actors[0].name, 'APT29');
});

test('follow-up real do mesmo veículo em outro dia agrupa quando tem evidência forte', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Gateway exploitation', link: 'https://a.example/1', cves: ['CVE-2026-12345'], pubDate: daysBefore(2) }),
        item({ title: 'Gateway exploitation', link: 'https://a.example/2', cves: ['CVE-2026-12345'] }),
    ], NOW);
    assert.equal(stories.length, 1);
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

test('uma união não empresta sinais para fabricar a próxima união', () => {
    const seed = mergeIntoStories([], [
        item({ title: 'Oracle database', link: 'https://a.example/1', cves: ['CVE-1'], pubDate: daysBefore(1) }),
        item({ title: 'Oracle scandal', link: 'https://b.example/2', pubDate: daysBefore(1) }),
    ], NOW);
    assert.equal(seed.length, 2, 'A and B remain separate: Jaccard = 0.33');

    const bridged = mergeIntoStories(seed, [item({
        title: 'Scandal', link: 'https://c.example/3',
        cves: ['CVE-1'],
    })], NOW);
    assert.equal(bridged.length, 2, 'a ponte não tem evidência direta para a segunda história');
    assert.equal(bridged.find((story) => story.cves.includes('CVE-1')).sources.length, 2);
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
    assert.equal(mesmoDia.length, 2, 'beta e stable são releases diferentes mesmo no mesmo dia');
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

// ─── Malware em comum e sobreposição de IOC ────────────────────────────────

test('malware em comum une quando há também um termo raro em comum', () => {
    const lumma = [{ id: 'm1', name: 'LummaC2', matched: 'LummaC2', via: 'distinctive' }];
    const stories = mergeIntoStories([], [
        item({ title: 'LummaC2 infrastructure seized by Europol', link: 'https://a.example/1', malware: lumma }),
        item({ title: 'Europol disrupts LummaC2 stealer operation', link: 'https://b.example/2', malware: lumma }),
    ], NOW);
    assert.equal(stories.length, 1);
});

// Mesma família, vítimas diferentes: a popularidade de uma família comum
// (LummaC2/AsyncRAT/RedLine) gera manchete nova toda semana por motivo não
// relacionado — tratar "mesma família" como prova de "mesma história" seria um
// eixo de falso-merge pior que o caso análogo do ator (Cl0p/Fortra acima).
test('malware em comum sem termo raro em comum não une', () => {
    const lumma = [{ id: 'm1', name: 'LummaC2', matched: 'LummaC2', via: 'distinctive' }];
    const stories = mergeIntoStories([], [
        item({ title: 'LummaC2 infects victims via fake CAPTCHA', link: 'https://a.example/1', malware: lumma }),
        item({ title: 'LummaC2 found on compromised university network', link: 'https://b.example/2', malware: lumma }),
    ], NOW);
    assert.equal(stories.length, 2);
});

test('hash em comum une, mesmo com títulos sem palavra em comum', () => {
    const hash = 'a'.repeat(64);
    const stories = mergeIntoStories([], [
        item({ title: 'Researchers publish malware teardown', link: 'https://a.example/1', iocs: { hashes: [hash], ips: [], domains: [], urls: [] } }),
        item({ title: 'Vendor ships signature update', link: 'https://b.example/2', iocs: { hashes: [hash], ips: [], domains: [], urls: [] } }),
    ], NOW);
    assert.equal(stories.length, 1);
});

test('domínio e URL em comum também unem sozinhos', () => {
    for (const iocs of [
        { hashes: [], ips: [], domains: ['evil-c2.example'], urls: [] },
        { hashes: [], ips: [], domains: [], urls: ['http://evil-c2.example/panel'] },
    ]) {
        const stories = mergeIntoStories([], [
            item({ title: 'Blog post about a new campaign', link: `https://a.example/${Math.random()}`, iocs }),
            item({ title: 'Totally different writeup, no shared words', link: `https://b.example/${Math.random()}`, iocs }),
        ], NOW);
        assert.equal(stories.length, 1, JSON.stringify(iocs));
    }
});

test('IP puro em comum sem corroboração não une; com corroboração une', () => {
    const ip = { hashes: [], ips: ['203.0.113.9'], domains: [], urls: [] };
    const semCorroboracao = mergeIntoStories([], [
        item({ title: 'Quarterly earnings report published today', link: 'https://a.example/1', iocs: ip }),
        item({ title: 'Local election results announced tonight', link: 'https://b.example/2', iocs: ip }),
    ], NOW);
    assert.equal(semCorroboracao.length, 2, 'IP sozinho não é suficiente — hospedagem reusa endereço entre campanhas');

    const lumma = [{ id: 'm1', name: 'LummaC2', matched: 'LummaC2', via: 'distinctive' }];
    const comCorroboracao = mergeIntoStories([], [
        item({ title: 'LummaC2 command panel discovered online', link: 'https://c.example/1', iocs: ip, malware: lumma }),
        item({ title: 'Takedown of the LummaC2 panel completed', link: 'https://d.example/2', iocs: ip, malware: lumma }),
    ], NOW);
    assert.equal(comCorroboracao.length, 1, 'IP com ator/malware em comum é evidência suficiente');
});

test('fonte com manchete de apanhado não empresta IOC pra regra de merge', () => {
    // Mesmo guard que já existe pra CVE: um post "indicadores da semana" não
    // pode virar eixo de merge entre campanhas sem relação.
    const hash = 'b'.repeat(64);
    const stories = mergeIntoStories([], [
        item({ title: 'Weekly recap of indicators', link: 'https://a.example/1', iocs: { hashes: [hash], ips: [], domains: [], urls: [] } }),
        item({ title: 'Completely unrelated single-campaign report', link: 'https://b.example/2', iocs: { hashes: [hash], ips: [], domains: [], urls: [] } }),
    ], NOW);
    assert.equal(stories.length, 2, 'o resumo semanal não deveria colar as duas matérias');
});

// Extensão do teste de ator (linha ~61): sem subtrair também os tokens do
// nome do malware, duas stories não relacionadas compartilhando ator E
// malware, mas nenhum outro termo, uniriam só com o nome das entidades.
test('rareBeyondEntities exclui nomes de ator e de malware, não só de ator', () => {
    const cl0p = [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }];
    const lumma = [{ id: 'm1', name: 'LummaC2', matched: 'LummaC2', via: 'distinctive' }];
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p and LummaC2 both mentioned in roundup', link: 'https://a.example/1', actors: cl0p, malware: lumma }),
        item({ title: 'Cl0p and LummaC2 unrelated second mention', link: 'https://b.example/2', actors: cl0p, malware: lumma }),
    ], NOW);
    assert.equal(stories.length, 2, 'ator e malware em comum sem mais nenhum termo raro não deveria unir');
});

// ─── Campanha em comum e sobreposição de TTP ───────────────────────────────

test('campanha em comum une sozinha, sem precisar de termo raro em comum', () => {
    const dreamJob = [{ id: 'c1', name: 'Operation Dream Job', matched: 'Operation Dream Job', via: 'multiword' }];
    const stories = mergeIntoStories([], [
        item({ title: 'New details emerge about a 2019 espionage operation', link: 'https://a.example/1', campaigns: dreamJob }),
        item({ title: 'Researchers reconstruct timeline of a Lazarus operation', link: 'https://b.example/2', campaigns: dreamJob }),
    ], NOW);
    assert.equal(stories.length, 1, 'uma campanha nomeada identifica uma operação específica, suficiente por si só');
});

test('fonte com manchete de apanhado não empresta campanha pra regra de merge', () => {
    const campaigns = [
        { id: 'c1', name: 'Operation Dream Job', matched: 'Operation Dream Job', via: 'multiword' },
    ];
    const stories = mergeIntoStories([], [
        item({ title: 'Weekly recap of notable APT campaigns', link: 'https://a.example/1', campaigns }),
        item({ title: 'Totally unrelated single-operation report', link: 'https://b.example/2', campaigns }),
    ], NOW);
    assert.equal(stories.length, 2, 'o resumo semanal não deveria colar as duas matérias');
});

test('fonte com mais campanhas que o teto não empresta nenhuma', () => {
    const many = ['c1', 'c2', 'c3', 'c4'].map((id) => ({ id, name: id, matched: id, via: 'distinctive' }));
    const stories = mergeIntoStories([], [
        item({ title: 'Year in review: four notable operations', link: 'https://a.example/1', campaigns: many }),
        item({ title: 'Totally unrelated single-operation report', link: 'https://b.example/2', campaigns: [many[0]] }),
    ], NOW);
    assert.equal(stories.length, 2, 'um apanhado com mais de MAX_TOPIC_CAMPAIGNS não deveria emprestar campanha nenhuma');
});

test('contexto suficiente do título pode unir; TTP não reduz o limiar', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'New phishing kit targets banking customers', link: 'https://a.example/1', ttpIds: ['T1566'] }),
        item({ title: 'Banking customers hit by fresh phishing wave', link: 'https://b.example/2', ttpIds: ['T1566'] }),
    ], NOW);
    assert.equal(stories.length, 1);
});

test('TTP em comum sem termo raro em comum não une', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Quarterly earnings report published today', link: 'https://a.example/1', ttpIds: ['T1566'] }),
        item({ title: 'Local election results announced tonight', link: 'https://b.example/2', ttpIds: ['T1566'] }),
    ], NOW);
    assert.equal(stories.length, 2, 'T1566 é comum demais pra provar que é a mesma história sozinho');
});
