import test from 'node:test';
import assert from 'node:assert/strict';
import { actorTargeting } from '../actorProfile.js';

test('deriva setor e região a partir da frase de vitimologia', () => {
    const { sectors, targets } = actorTargeting({
        country: 'China',
        description: 'APT-X is a China-based group. It has targeted banking and healthcare organizations in Taiwan and Japan.',
    });
    assert.deepEqual(sectors.sort(), ['Financial', 'Healthcare']);
    assert.deepEqual(targets.sort(), ['Japan', 'Taiwan']);
});

test('país de origem não vira alvo, nem pela atribuição nem pela frase', () => {
    const { targets } = actorTargeting({
        country: 'Russia',
        description: 'A Russian state-sponsored actor. The group has attacked Ukrainian and Russian dissident entities.',
    });
    assert.deepEqual(targets, ['Ukraine']);
});

test('frase sem pista de vítima não gera alvo nem setor', () => {
    assert.deepEqual(
        actorTargeting({ country: 'Iran', description: 'Suspected Iranian group first reported in 2015.' }),
        { sectors: [], targets: [] },
    );
});

test('descrição ausente não quebra', () => {
    assert.deepEqual(actorTargeting({}), { sectors: [], targets: [] });
    assert.deepEqual(actorTargeting(), { sectors: [], targets: [] });
});
