import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePtbrHunt, isHuntPath } from '../huntsPtbr.js';

// Cópia fiel de hunts/weekly/top-egress-and-denied-traffic.md.
const HUNT = `# Principais saídas e tráfego negado

## Objetivo
Volume de saída de linha de base, destinos, usuários e atividade de rede bloqueada.

## Cadência
Caça Semanal

## Tabelas Sentinel
- [CommonSecurityLog](../../sentinel/tables/reference/CommonSecurityLog.md)
- [NetskopeEventsNetwork_CL](../../sentinel/tables/reference/NetskopeEventsNetwork_CL.md)
- [Cloudflare_CL](../../sentinel/tables/reference/Cloudflare_CL.md)

## Ferramentas
- [Fortigate](../../tools/firewall/fortigate.md)
- [Netskope](../../tools/sase/netskope.md)

## KQL
[\`weekly/top-egress-and-denied-traffic.kql\`](../../sentinel/kql/weekly/top-egress-and-denied-traffic.kql)

## Fluxo de trabalho do analista
1. Confirme a integridade da fonte de dados nas tabelas acima.
2. Execute KQL com o lookback padrão.

## Resultado Esperado
- Descobertas confirmadas ou falsos positivos documentados.
`;

test('extrai hunt do markdown do repo', () => {
    const hunt = parsePtbrHunt(HUNT, 'hunts/weekly/top-egress-and-denied-traffic.md');

    assert.equal(hunt.title, 'Principais saídas e tráfego negado');
    assert.equal(hunt.id, 'weekly/top-egress-and-denied-traffic');
    assert.equal(hunt.origin, 'ptbr');
    assert.equal(hunt.cadence, 'weekly');
    assert.match(hunt.hypothesis, /Volume de saída de linha de base/);
    // O texto do link vira a tabela; o caminho do arquivo fica de fora.
    assert.deepEqual(hunt.dataSources, ['CommonSecurityLog', 'NetskopeEventsNetwork_CL', 'Cloudflare_CL']);
    assert.deepEqual(hunt.technologies, ['Fortigate', 'Netskope']);
    assert.match(hunt.queryPath, /sentinel\/kql\/weekly\/top-egress-and-denied-traffic\.kql$/);
    assert.match(hunt.notes, /Execute KQL com o lookback padrão/);
    assert.match(hunt.expected, /falsos positivos documentados/);
});

test('cadência sai do caminho quando a seção não diz', () => {
    const semCadencia = '# Varredura\n\n## Objetivo\nvarrer IOCs\n';
    assert.equal(parsePtbrHunt(semCadencia, 'hunts/daily/ioc.md').cadence, 'daily');
    assert.equal(parsePtbrHunt(semCadencia, 'hunts/monthly/ioc.md').cadence, 'monthly');
    assert.equal(parsePtbrHunt(semCadencia, 'hunts/solto/ioc.md').cadence, '');
});

test('hunt sem objetivo cai pro título, e sem título estoura', () => {
    const semObjetivo = parsePtbrHunt('# Só o título\n\n## Cadência\nDiária\n', 'hunts/daily/x.md');
    assert.equal(semObjetivo.hypothesis, 'Só o título');
    assert.throws(() => parsePtbrHunt('## Objetivo\nsem cabeçalho\n', 'hunts/daily/y.md'), /sem título/);
});

test('README de pasta não é hunt', () => {
    assert.equal(isHuntPath('hunts/weekly/top-egress-and-denied-traffic.md'), true);
    assert.equal(isHuntPath('hunts/weekly/README.md'), false);
    assert.equal(isHuntPath('hunts/README.md'), false);
    assert.equal(isHuntPath('sentinel/kql/weekly/x.kql'), false);
});
