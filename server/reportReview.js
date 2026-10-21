const fail = (message) => { throw Object.assign(new Error(message), { status: 400 }); };
const text = (value, limit, field) => {
    if (typeof value !== 'string' || value.length > limit) fail(`Campo inválido: ${field}.`);
    return value.trim();
};

/** Allow only editorial changes; source evidence and original report remain intact. */
export function reviewReport(original, patch = {}) {
    if (!original || !['campaign', 'vuln'].includes(original.deck_type)) fail('Relatório incompatível com a geração de slides.');
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) fail('Revisão inválida.');
    const allowed = new Set(['titulo', 'sumario_executivo', 'descricao', 'recomendacoes', 'mitre_ttps']);
    for (const key of Object.keys(patch)) if (!allowed.has(key)) fail(`Campo não editável: ${key}.`);
    const report = structuredClone(original);
    for (const [field, limit] of [['titulo', 300], ['sumario_executivo', 16000], ['descricao', 24000]]) {
        if (field in patch) {
            report[field] = text(patch[field], limit, field);
            if (!report[field]) fail(`Preencha ${field}.`);
        }
    }
    if ('recomendacoes' in patch) {
        if (!Array.isArray(patch.recomendacoes) || patch.recomendacoes.length > 8) fail('Recomendações inválidas.');
        report.recomendacoes = patch.recomendacoes.map(group => {
            if (!group || !Array.isArray(group.itens) || group.itens.length > 15) fail('Grupo de recomendações inválido.');
            return { titulo: text(group.titulo, 120, 'categoria'), itens: group.itens.map(item => text(item, 1500, 'recomendação')).filter(Boolean) };
        });
        // Premium and advanced templates prefer the structured SRR recommendations.
        // Rebuild those from the reviewed groups rather than retaining stale text.
        if (report.srr_avancado) {
            delete report.srr_avancado.recomendacoes;
            delete report.srr_avancado.acoes_prioritarias;
        }
    }
    if ('mitre_ttps' in patch) {
        if (!Array.isArray(patch.mitre_ttps) || !patch.mitre_ttps.length || patch.mitre_ttps.length > 30) fail('Mantenha ao menos uma técnica MITRE.');
        const known = new Map((original.mitre_ttps || []).map(row => [row.id, row]));
        const seen = new Set();
        report.mitre_ttps = patch.mitre_ttps.map(row => {
            if (!row || !known.has(row.id) || seen.has(row.id)) fail('Técnica MITRE inválida ou duplicada.');
            seen.add(row.id);
            const contexto = text(row.contexto, 1500, 'contexto MITRE');
            if (!/^\[(POTENCIAL|EM EXPLORAÇÃO)\]\s+\S/.test(contexto)) fail('Classifique cada contexto MITRE como POTENCIAL ou EM EXPLORAÇÃO.');
            const previous = known.get(row.id);
            return contexto === previous.contexto ? structuredClone(previous) : {
                ...structuredClone(previous), contexto, classificacao: 'revisao_manual',
                justificativa: 'Contexto e classificação revisados pelo analista. A citação automática, quando disponível, permanece para conferência.',
            };
        });
    }
    return report;
}
