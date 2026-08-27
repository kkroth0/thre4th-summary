// A OTX não devolve 429 e não manda header de cota: passando de umas cinco
// chamadas simultâneas ela simplesmente **para de responder**, e o socket morre
// virando 500 genérico. Como não há status pra detectar, não dá pra fazer o que
// o shodanGate faz (ler Retry-After e reagir) — só resta não passar do teto.
//
// O teto depende de haver chave, então o default também depende. Medido em
// 2026-08-27, de dois IPs diferentes:
//
//   sem chave (12 chamadas):  4 → 12/12 · 6 → 17/18 · 12 → 9/12
//   com chave (30 chamadas):  4 → 29/30 em 21s · 8 → 29/30 em 16s · 12 → 28/30
//
// Ou seja: com chave, 8 entrega o mesmo acerto de 4 e termina o lote 24% mais
// rápido; 12 já piora. Sem chave, 6 já começa a travar. Daí o default de 8 com
// chave e 4 sem — calibrar os dois no mesmo número pioraria um dos dois casos.
//
// Por isso este gate é de concorrência, não de espaçamento. E precisa de timeout
// próprio: sem ele uma chamada travada segura a vaga para sempre e o gate
// entope sozinho.

const MAX_CONCURRENT = Number(process.env.OTX_MAX_CONCURRENT)
    || (process.env.ALIENVAULT_API_KEY ? 8 : 4);
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
