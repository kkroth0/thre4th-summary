#!/usr/bin/env node
// Falha em qualquer vulnerabilidade alta ou crítica, menos as registradas aqui.
//
// Baixar o --audit-level pra "critical" silenciaria toda vulnerabilidade alta
// futura, que é o oposto do que a esteira serve. Aqui a exceção é nominal,
// datada e justificada — e qualquer advisory novo continua quebrando o build.
//
// Uso: node scripts/audit-check.mjs [--prefix server]

import { execFileSync } from 'node:child_process';

const ACCEPTED = [
    {
        id: 'GHSA-qwww-vcr4-c8h2',
        package: 'react-router',
        since: '2026-08-04',
        reason:
            'CSRF em modo RSC. Não aplicável: SPA estática no Cloudflare Pages, sem SSR e sem RSC. ' +
            'A faixa vulnerável é 7.12–8.2 e a única saída do npm audit é o downgrade forçado pra ' +
            '7.11, que quebra a aplicação. Revisar quando sair correção acima de 8.2.0.',
    },
    {
        id: 'GHSA-w3rx-r6r6-pgpr',
        package: 'image-size',
        since: '2026-08-10',
        reason:
            'DoS por loop infinito no parser ICNS. Não alcançável: o image-size entra só como ' +
            'dependência do pptxgenjs, e nenhum export chama addImage — os slides são texto puro, ' +
            'então nenhum parser de imagem roda. Não há versão corrigida (a faixa é <=2.0.2 e a ' +
            'última publicada é 2.0.2); o npm audit só oferece downgrade do pptxgenjs 4 para 1.1.5, ' +
            'que quebra a exportação PPTX. Revisar quando sair image-size acima de 2.0.2.',
    },
    {
        id: 'GHSA-5p2g-fcmc-qvqq',
        package: 'image-size',
        since: '2026-08-10',
        reason: 'Mesma dependência e mesmo motivo do GHSA-w3rx-r6r6-pgpr, nos parsers JXL e HEIF.',
    },
];

const prefixIndex = process.argv.indexOf('--prefix');
const args = ['audit', '--json'];
if (prefixIndex > -1) args.unshift('--prefix', process.argv[prefixIndex + 1]);

let report;
try {
    report = JSON.parse(execFileSync('npm', args, { encoding: 'utf8', maxBuffer: 20e6 }));
} catch (error) {
    // npm sai com código != 0 quando acha algo; o relatório vem no stdout mesmo.
    if (!error.stdout) throw error;
    report = JSON.parse(error.stdout);
}

const accepted = new Set(ACCEPTED.map((item) => item.id));
const blocking = [];

for (const [name, entry] of Object.entries(report.vulnerabilities || {})) {
    if (!['high', 'critical'].includes(entry.severity)) continue;

    // `via` mistura strings (dependência transitiva) e objetos (o advisory em si).
    const advisories = (entry.via || []).filter((item) => typeof item === 'object');
    const ids = advisories.map((item) => String(item.url || '').split('/').pop()).filter(Boolean);

    // Sem advisory próprio, o pacote só herda de outro: quem responde é a raiz.
    if (!ids.length) continue;
    if (ids.every((id) => accepted.has(id))) continue;

    blocking.push(`${name} (${entry.severity}): ${ids.filter((id) => !accepted.has(id)).join(', ')}`);
}

const scope = prefixIndex > -1 ? process.argv[prefixIndex + 1] : 'raiz';

if (blocking.length) {
    console.error(`Vulnerabilidades altas sem exceção registrada (${scope}):`);
    for (const line of blocking) console.error(`  - ${line}`);
    console.error('\nRegistre a exceção em scripts/audit-check.mjs com motivo e data, ou corrija.');
    process.exit(1);
}

console.log(`Sem vulnerabilidade alta pendente (${scope}).`);
for (const item of ACCEPTED) console.log(`  exceção ativa: ${item.package} ${item.id} desde ${item.since}`);
