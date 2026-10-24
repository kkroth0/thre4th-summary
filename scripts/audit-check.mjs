#!/usr/bin/env node
// Falha em qualquer vulnerabilidade alta ou crítica, menos as registradas aqui.
//
// Baixar o --audit-level pra "critical" silenciaria toda vulnerabilidade alta
// futura, que é o oposto do que a esteira serve. Aqui a exceção é nominal,
// datada e justificada — e qualquer advisory novo continua quebrando o build.
//
// Uso: node scripts/audit-check.mjs [--prefix server]

import { execFileSync } from 'node:child_process';

// No accepted high/critical advisories remain after the 2026-10-24 update.
const ACCEPTED = [];

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
