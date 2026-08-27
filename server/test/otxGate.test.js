import test from 'node:test';
import assert from 'node:assert/strict';
import { otxThrottled, otxGateState, OTX_TIMEOUT_MS } from '../otxGate.js';

// O default depende de haver chave (8 com, 4 sem): o teste roda sem
// ALIENVAULT_API_KEY no ambiente, então o teto aqui é 4.
const MAX = otxGateState().max;

const deferred = () => {
    let resolve, reject;
    const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
    return { promise, resolve, reject };
};

// O teto é a razão de o módulo existir: passar dele é o que faz a OTX parar de
// responder, e ela não avisa por status nenhum.
test('nunca passa do teto de chamadas em voo, e o excedente espera', async () => {
    assert.equal(MAX, 4, 'sem chave no ambiente do teste, o teto é 4');
    const gates = Array.from({ length: MAX + 3 }, deferred);
    let concorrentesNoPico = 0;
    let emVoo = 0;

    const calls = gates.map((gate) => otxThrottled(async () => {
        emVoo += 1;
        concorrentesNoPico = Math.max(concorrentesNoPico, emVoo);
        await gate.promise;
        emVoo -= 1;
        return 'ok';
    }));

    await new Promise((r) => setImmediate(r));
    assert.equal(emVoo, MAX, 'só o teto entra de cara');
    assert.equal(otxGateState().waiting, 3, 'o excedente fica na fila');

    gates.forEach((g) => g.resolve());
    assert.deepEqual(await Promise.all(calls), Array(MAX + 3).fill('ok'));
    assert.equal(concorrentesNoPico, MAX);
});

// Uma chamada que estoura não pode segurar a vaga: era assim que o gate
// entupiria sozinho depois do primeiro timeout.
test('chamada que falha devolve a vaga', async () => {
    await assert.rejects(otxThrottled(async () => { throw new Error('timeout of 15000ms exceeded'); }));
    assert.deepEqual(otxGateState(), { active: 0, waiting: 0, max: MAX });
    assert.equal(await otxThrottled(async () => 'passou'), 'passou');
});

test('a fila esvazia até zerar o contador', async () => {
    await Promise.all(Array.from({ length: 10 }, () => otxThrottled(async () => 'ok')));
    assert.deepEqual(otxGateState(), { active: 0, waiting: 0, max: MAX });
});

// Sem timeout a chamada travada da OTX (que nunca responde) segura a vaga para
// sempre — o gate precisa de um teto de tempo, não só de concorrência.
test('o timeout está definido e é finito', () => {
    assert.ok(Number.isFinite(OTX_TIMEOUT_MS) && OTX_TIMEOUT_MS > 0);
});
