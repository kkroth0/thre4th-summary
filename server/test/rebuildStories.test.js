import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// fileURLToPath, not .pathname: on Windows, a file:// URL's .pathname keeps the
// leading slash ("/C:/Users/...") and spawning node with that gets the drive
// letter double-prefixed ("C:\C:\Users\..."), module-not-found, every time.
const SCRIPT = fileURLToPath(new URL('../rebuildStories.mjs', import.meta.url));

const source = (over) => ({ source: 'Feed', score: 50, severity: 'High', cves: [], ...over });

const run = (stories, args = []) => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'stories-')), '.news-stories.json');
    fs.writeFileSync(file, JSON.stringify(stories));
    const stdout = execFileSync('node', [SCRIPT, ...args, file], { encoding: 'utf8' });
    return { file, stdout, result: JSON.parse(fs.readFileSync(file, 'utf8')) };
};

test('o dry-run não toca no arquivo', () => {
    const stories = [{ id: 'a', title: 'T', firstSeen: '2026-08-11T12:00:00Z', lastSeen: '2026-08-11T12:00:00Z', cves: [], actors: [], categories: [], sources: [source({ link: 'https://x.example/1', title: 'T', pubDate: '2026-08-11T12:00:00Z' })] }];
    const { file, stdout, result } = run(stories);
    assert.match(stdout, /dry-run/);
    assert.deepEqual(result, stories);
    assert.ok(!fs.existsSync(`${file}.bak`), 'dry-run não devia deixar .bak');
});

// As duas metades do conserto, no mesmo arquivo: o card errado se desfaz, e o
// card que estava certo não perde o rótulo que veio da descrição do artigo.
test('reagrupa, guarda .bak e devolve a categoria de quem continuou inteiro', () => {
    const { file, result } = run([
        {
            // Duas edições de release do mesmo veículo em dias diferentes: as
            // regras atuais separam. A categoria aqui é do card errado e não
            // pode seguir nenhuma das metades.
            id: 'chrome', title: 'Chrome for Android Update',
            firstSeen: '2026-08-06T12:00:00Z', lastSeen: '2026-08-11T12:00:00Z',
            cves: [], actors: [], categories: ['Microsoft'], primaryCategory: 'Microsoft',
            sources: [
                source({ source: 'Chrome Releases', link: 'https://chrome.example/1', title: 'Chrome Beta for Android Update', pubDate: '2026-08-06T12:00:00Z' }),
                source({ source: 'Chrome Releases', link: 'https://chrome.example/2', title: 'Chrome for Android Update', pubDate: '2026-08-11T12:00:00Z' }),
            ],
        },
        {
            // Título não diz o assunto — 'Ransomware' veio do texto do artigo,
            // que a fonte gravada não guarda. Sem a devolução, o card perderia
            // a categoria no reagrupamento.
            id: 'op', title: 'Ataque derruba operadora regional',
            firstSeen: '2026-08-10T12:00:00Z', lastSeen: '2026-08-10T12:00:00Z',
            cves: [], actors: [], categories: ['Ransomware'], primaryCategory: 'Ransomware',
            sources: [source({ source: 'CISO Advisor BR', link: 'https://ciso.example/op', title: 'Ataque derruba operadora regional', pubDate: '2026-08-10T12:00:00Z' })],
        },
    ], ['--write']);

    assert.ok(fs.existsSync(`${file}.bak`), 'o .bak não foi gravado');
    assert.equal(result.length, 3, 'as duas edições do Chrome continuaram num card só');

    const operadora = result.find((story) => story.sources[0].link === 'https://ciso.example/op');
    assert.deepEqual(operadora.categories, ['Ransomware']);
    assert.equal(operadora.primaryCategory, 'Ransomware');

    for (const story of result.filter((s) => s.sources[0].source === 'Chrome Releases')) {
        assert.deepEqual(story.categories, [], 'a categoria do card errado seguiu para as metades');
    }
});

// A fonte gravada guarda iocs por artigo (newStory() em newsStories.js). Sem
// reconstruir esse campo aqui, um rebuild depois de mudar a regra de merge por
// IOC perderia essa evidência em silêncio — real lacuna achada lendo o arquivo.
test('IOC da fonte gravada é reconstruído e permite remesclar por ele', () => {
    // rebuildStories.mjs chama mergeIntoStories com `new Date()` real, sem
    // receber `now` por parâmetro — datas fixas no passado cairiam fora da
    // janela de 14 dias (STORY_ACTIVE_DAYS) e nunca chegariam a comparar entre
    // si, mascarando o próprio sinal que este teste quer verificar.
    const hash = 'c'.repeat(64);
    const pubA = new Date(Date.now() - 2 * 86400000).toISOString();
    const pubB = new Date(Date.now() - 1 * 86400000).toISOString();
    const { result } = run([
        {
            id: 'a', title: 'Primeira matéria sem nenhuma palavra em comum',
            firstSeen: pubA, lastSeen: pubA,
            cves: [], actors: [], categories: [],
            sources: [source({
                link: 'https://x.example/1', title: 'Primeira matéria sem nenhuma palavra em comum',
                pubDate: pubA, iocs: { hashes: [hash], ips: [], domains: [], urls: [] },
            })],
        },
        {
            id: 'b', title: 'Segunda matéria totalmente diferente da primeira',
            firstSeen: pubB, lastSeen: pubB,
            cves: [], actors: [], categories: [],
            sources: [source({
                link: 'https://x.example/2', title: 'Segunda matéria totalmente diferente da primeira',
                pubDate: pubB, iocs: { hashes: [hash], ips: [], domains: [], urls: [] },
            })],
        },
    ], ['--write']);

    assert.equal(result.length, 1, 'o hash compartilhado devia remesclar as duas em uma história só');
    assert.equal(result[0].sources.length, 2);
});
