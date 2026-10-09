// Arquivo permanente do feed: link, título, fonte, data e categorias de todo
// item que já passou pelo boletim — nunca podado, ao contrário de
// newsStoryStore (60 dias) e do feed em memória (10 minutos de TTL). O pedido
// original foi "quero conseguir armazenar estas notícias, todas, os links e
// as categorias" — isto é a base de dados pra isso, consultável e exportável,
// sem tela nova. Mesmo padrão de fs-por-injeção do createStoryStore.
export function createNewsArchiveStore({ filePath, readFileSync, writeJsonAtomic }) {
    let rows = [];
    let seen = new Set();
    try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
        rows = Array.isArray(parsed) ? parsed.filter((r) => r && r.link) : [];
        seen = new Set(rows.map((r) => r.link));
    } catch { /* arquivo ausente ou corrompido: arquivo vazio, não derruba o servidor */ }

    return {
        all: () => rows,
        size: () => rows.length,
        /**
         * Adiciona só links ainda não vistos — um link já arquivado mantém a
         * categoria da primeira vez que entrou, mesmo que o motor de
         * categorização mude depois. Devolve quantos de fato entraram.
         */
        add(items) {
            const additions = [];
            for (const item of Array.isArray(items) ? items : []) {
                if (!item || !item.link || seen.has(item.link)) continue;
                additions.push({
                    link: item.link,
                    title: item.title || '',
                    source: item.source || '',
                    pubDate: item.pubDate || '',
                    categories: Array.isArray(item.categories) ? item.categories : [],
                    primaryCategory: item.primaryCategory || null,
                    // Vazio pra item fora da categoria Phishing — é o que o
                    // dashboard de tendências (/phishing-analyzer) quebra por
                    // sub-técnica (ClickFix, AiTM, Vishing...).
                    phishingTechniques: Array.isArray(item.phishingTechniques) ? item.phishingTechniques : [],
                    archivedAt: new Date().toISOString(),
                });
            }
            if (!additions.length) return 0;
            // Escreve primeiro: se writeJsonAtomic estourar, a memória não pode
            // avançar além do que está em disco, senão um restart reprocessa o
            // mesmo lote e ele passa a faltar pra sempre (seen já teria essas
            // chaves se a memória tivesse avançado sem o disco acompanhar).
            const next = [...rows, ...additions];
            writeJsonAtomic(filePath, next);
            rows = next;
            for (const row of additions) seen.add(row.link);
            return additions.length;
        },
        list({ category, source, from, to, limit } = {}) {
            let result = rows;
            if (category) result = result.filter((r) => (r.categories || []).includes(category));
            if (source) result = result.filter((r) => r.source === source);
            if (from) {
                const cutoff = new Date(from).getTime();
                if (!Number.isNaN(cutoff)) result = result.filter((r) => new Date(r.pubDate).getTime() >= cutoff);
            }
            if (to) {
                const cutoff = new Date(to).getTime();
                if (!Number.isNaN(cutoff)) result = result.filter((r) => new Date(r.pubDate).getTime() <= cutoff);
            }
            // Mais recente primeiro — mesma ordem padrão do feed.
            result = [...result].sort((a, b) => String(b.pubDate).localeCompare(String(a.pubDate)));
            return limit ? result.slice(0, Number(limit)) : result;
        },
    };
}
