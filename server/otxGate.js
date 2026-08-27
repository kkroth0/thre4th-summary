// A OTX não devolve 429 e não manda header de cota: passando de umas cinco
// chamadas simultâneas ela simplesmente **para de responder**, e o socket morre
// virando 500 genérico. Como não há status pra detectar, não dá pra fazer o que
// o shodanGate faz (ler Retry-After e reagir) — só resta não passar do teto.
//
// Medido em 2026-08-27, sem chave, de dois IPs diferentes:
//   4 simultâneas → 12/12 ok · 6 → 17/18 · 12 → 9/12 (as 3 restantes travam)
//
// Por isso este gate é de concorrência, não de espaçamento. E precisa de timeout
// próprio: sem ele uma chamada travada segura a vaga para sempre e o gate
// entope sozinho.

const MAX_CONCURRENT = Number(process.env.OTX_MAX_CONCURRENT) || 4;
export const OTX_TIMEOUT_MS = Number(process.env.OTX_TIMEOUT_MS) || 15000;

let active = 0;
const waiting = [];

const acquire = () =>
    new Promise((resolve) => {
        if (active < MAX_CONCURRENT) {
            active += 1;
            resolve();
        } else {
            waiting.push(resolve);
        }
    });

// A vaga passa direto para quem está na fila — `active` só cai quando não há
// mais ninguém esperando, senão dois entram na mesma vaga.
const release = () => {
    const next = waiting.shift();
    if (next) next();
    else active -= 1;
};

// ponytail: fila em memória de um processo só. Duas instâncias dividindo o mesmo
// IP de saída teriam cada uma seu próprio teto — mover o contador pro Redis se
// um dia rodar replicado.
export const otxThrottled = async (call) => {
    await acquire();
    try {
        return await call();
    } finally {
        release();
    }
};

// Sem retry de propósito: se a OTX travou é porque já está limitando, e repetir
// na hora só empurra a fila. O gate existe pra não chegar nesse ponto.

export const otxGateState = () => ({ active, waiting: waiting.length, max: MAX_CONCURRENT });
