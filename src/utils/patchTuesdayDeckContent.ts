// The PT-BR prose the Patch Tuesday deck is built from — the opening paragraph,
// the "prioridades imediatas" bullets, the impact glossary, the zero-day
// definition and the closing recommendations. It lives here, apart from the
// PPTX writer, so the PowerPoint export and the CTIFLOW JSON export compose the
// same sentences from the same numbers and can never disagree.
import type { PatchTuesdaySummary, PatchVulnerability, NamedCount } from '@/services/msrcApi';
import { condenseTitle, fmtMonthPt } from './deckTemplate';

// ---- Vocabulary -------------------------------------------------------------

// Product families: the deck says these three in PT-BR; everything else MSRC
// already publishes in a form the reader recognises, so it passes through.
export const FAMILY_PT: Record<string, string> = {
    'Azure & Cloud': 'Azure e nuvem',
    'Developer Tools & .NET': 'Ferramentas de desenvolvimento e .NET',
    'Other Microsoft Products': 'Outros produtos Microsoft',
};

// Short forms for the highlight-card tag, where the full impact name would wrap.
export const IMPACT_SHORT: Record<string, string> = {
    'Remote Code Execution': 'RCE',
    'Elevation of Privilege': 'EoP',
    'Security Feature Bypass': 'Bypass',
    'Information Disclosure': 'Info. Disc.',
    'Denial of Service': 'DoS',
};

const SEVERITY_PT: Record<string, string> = {
    Critical: 'Crítica',
    Important: 'Importante',
    Moderate: 'Moderada',
    Low: 'Baixa',
    Unknown: 'Sem classificação',
};

export const IMPACT_GLOSSARY = [
    'Tampering: alteração não autorizada de dados, arquivos ou configurações.',
    'Security Feature Bypass: contorno de mecanismos e controles de segurança.',
    'DoS: interrupção ou indisponibilidade de sistemas e serviços.',
    'Spoofing: falsificação de identidade ou origem para enganar sistemas e usuários.',
    'Information Disclosure: exposição indevida de informações sensíveis ou confidenciais.',
    'Remote Code Execution (RCE): execução arbitrária de código no sistema afetado.',
    'Elevation of Privilege: obtenção de permissões superiores às originalmente concedidas.',
];

export const pt = (map: Record<string, string>, value: string) => map[value] || value;

export const familyPt = (name: string) => pt(FAMILY_PT, name);
export const impactShort = (name: string) => pt(IMPACT_SHORT, name);
export const severityPt = (name: string) => pt(SEVERITY_PT, name);

// Tag on the highlight cards: "EoP | Explor. ativa".
export const statusTagPt = (v: PatchVulnerability): string => {
    if (v.exploited) return 'Explor. ativa';
    if (v.publiclyDisclosed) return 'Pública';
    return v.severity === 'Critical' ? 'Crítica' : v.severity;
};

// Spelled-out status on the consolidated slide's zero-day mini cards.
export const statusLabelPt = (v: PatchVulnerability): string => {
    if (v.exploited) return 'Exploração ativa';
    if (v.publiclyDisclosed) return 'Publicamente divulgada';
    return v.severity === 'Critical' ? 'Crítica' : v.severity;
};

// ---- Zero-days ------------------------------------------------------------

// Zero-days are the CVEs Microsoft flags as exploited or already public. The
// full catalog is the source of truth; topCves stands in when a caller hands
// over a summary without it.
export const zeroDays = (s: PatchTuesdaySummary): PatchVulnerability[] => {
    const isZeroDay = (v: PatchVulnerability) => v.exploited || v.publiclyDisclosed;
    const fromCatalog = s.vulnerabilities.filter(isZeroDay);
    return fromCatalog.length ? fromCatalog : s.topCves.filter(isZeroDay);
};

// The impact mix of the critical set — the right column of the consolidated
// slide. `vulnerabilities` is the full catalog; when a caller hands over a
// summary without it, the cycle-wide impact split is the honest stand-in.
export const criticalImpactMix = (s: PatchTuesdaySummary): NamedCount[] => {
    const counts = new Map<string, number>();
    for (const v of s.vulnerabilities) {
        if (v.severity !== 'Critical') continue;
        counts.set(v.impact, (counts.get(v.impact) || 0) + 1);
    }
    const rows = [...counts.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count);
    return (rows.length ? rows : s.byImpact).slice(0, 4);
};

// ---- Executive summary prose -------------------------------------------------

// "Windows (CVE-2026-1), Windows (CVE-2026-2)" — the zero-day roll-call.
export const zeroDaysLine = (s: PatchTuesdaySummary): string =>
    zeroDays(s)
        .map((v) => `${v.family} (${v.cve})`)
        .join(', ');

// The sentence that explains the gap between the cover number and the press
// coverage. Empty when there are no upstream republications to account for.
export const upstreamNote = (s: PatchTuesdaySummary): string =>
    s.totals.upstream > 0
        ? `${s.totals.upstream} CVEs de código upstream (Chromium/Edge e pacotes do Azure Linux) ficam fora da contagem: são republicações da Microsoft, não correções em produtos próprios.`
        : '';

// The opening paragraph, split into the runs the PPTX writer needs to bold
// some of them. `executiveParagraph` re-joins them into plain text for JSON.
export const executiveOpeningParts = (s: PatchTuesdaySummary) => {
    const t = s.totals;
    const zds = zeroDays(s);
    return {
        lead: `O ciclo de ${fmtMonthPt(s.initialReleaseDate)} corrige `,
        total: `${t.total} vulnerabilidades`,
        mid: ', incluindo ',
        emphasis: `${t.critical} críticas e ${zds.length} zero-days`,
        end: '. ',
        zeroDaysLabel: zds.length ? 'Zero-Days: ' : '',
        zeroDaysList: zds.length ? `${zeroDaysLine(s)}. ` : '',
        upstreamNote: upstreamNote(s),
    };
};

export const executiveParagraph = (s: PatchTuesdaySummary): string => {
    const p = executiveOpeningParts(s);
    return (
        p.lead + p.total + p.mid + p.emphasis + p.end + p.zeroDaysLabel + p.zeroDaysList + p.upstreamNote
    ).trim();
};

// The four "prioridades imediatas" bullets on the executive summary slide.
export const immediatePriorities = (s: PatchTuesdaySummary): string[] => {
    const t = s.totals;
    const zds = zeroDays(s);
    const out: string[] = [];
    if (t.exploited > 0) {
        const targets = zds.filter((v) => v.exploited).map((v) => v.family);
        out.push(
            `Priorizar imediatamente ${targets.length ? targets.join(' e ') : 'os ativos expostos'}, considerando a existência de vulnerabilidades já exploradas em ataques.`
        );
    }
    if (t.disclosed > 0) {
        out.push(
            `Antecipar a correção das ${t.disclosed} CVE(s) divulgadas publicamente: detalhes de exploração podem já estar circulando.`
        );
    }
    out.push(
        `Acelerar a atualização de ${s.byFamily.slice(0, 4).map((f) => familyPt(f.name)).join(', ')}, priorizando serviços de identidade, segurança e colaboração.`
    );
    out.push(
        'Validar a aplicação dos patches nos ativos afetados, acompanhar falhas de instalação e tratar rapidamente sistemas sem suporte, exceções ou atualizações pendentes.'
    );
    return out;
};

// "46 Diversas", "40 Remote Code Execution", … — the critical-set impact list.
export const criticalImpactLines = (s: PatchTuesdaySummary): string[] =>
    criticalImpactMix(s).map((r) => `${r.count} ${r.name}`);

// ---- Recommendations (closing slide) --------------------------------------

export interface RecommendationBlock {
    index: number;
    title: string;
    body: string;
}

// Six standing recommendations. The first is written from the month's data —
// the actively exploited CVE, or the disclosed one, or the critical count — and
// the other five are the team's stable guidance, verbatim from the reference
// deck.
export const recommendationBlocks = (s: PatchTuesdaySummary): RecommendationBlock[] => {
    const zds = zeroDays(s);
    const exploited = zds.find((v) => v.exploited) ?? s.vulnerabilities.find((v) => v.exploited);
    const disclosed =
        zds.find((v) => v.publiclyDisclosed) ?? s.vulnerabilities.find((v) => v.publiclyDisclosed);

    let priority: string;
    if (exploited) {
        priority = `Considerar a priorização dos patches relacionados a ${exploited.title} (${exploited.cve}), devido à existência de exploração ativa reportada para a vulnerabilidade.`;
    } else if (disclosed) {
        priority = `Considerar a priorização dos patches relacionados a ${disclosed.title} (${disclosed.cve}), divulgada publicamente antes da disponibilização da correção.`;
    } else {
        priority = `Priorizar a aplicação das ${s.totals.critical} correções de severidade crítica deste ciclo, começando pelos ativos de maior exposição.`;
    }

    return [
        { index: 1, title: 'Correção Prioritária', body: priority },
        {
            index: 2,
            title: 'Infraestrutura Crítica',
            body: 'Avaliar a atualização de servidores Windows, DNS, DHCP e serviços de implantação, especialmente em ativos que suportam funções críticas do ambiente corporativo.',
        },
        {
            index: 3,
            title: 'Segurança dos Endpoints',
            body: 'Considerar a aplicação das correções disponibilizadas para Windows e Microsoft Defender, reduzindo a exposição a cenários de execução remota de código e elevação de privilégios.',
        },
        {
            index: 4,
            title: 'Proteção da Identidade',
            body: 'Recomenda-se revisar e atualizar os componentes relacionados à autenticação e gerenciamento de identidades, com atenção às vulnerabilidades que possam impactar privilégios locais em estações e servidores.',
        },
        {
            index: 5,
            title: 'Aplicações Corporativas',
            body: 'Avaliar a implementação das atualizações de segurança para Microsoft Office, Exchange Server e SharePoint Server, principalmente em ambientes que processam conteúdo corporativo ou possuem maior exposição operacional.',
        },
        {
            index: 6,
            title: 'Implantação e Governança',
            body: 'Sugere-se conduzir o processo de atualização de forma controlada, acompanhando eventuais falhas de instalação, exceções operacionais e ativos que permaneçam pendentes de correção.',
        },
    ];
};

// The speaker-notes block for the highlights slide.
export const highlightSpeakerNotes = (cards: PatchVulnerability[]): string =>
    cards
        .map((v) =>
            [
                v.cve,
                `Título completo: ${v.title}`,
                `Severidade: ${v.severity}${v.cvss == null ? '' : ` · CVSS ${v.cvss.toFixed(1)}`}`,
                `Impacto: ${v.impact} · Família: ${familyPt(v.family)}`,
                `Avaliação de exploração: ${v.exploitability}`,
                v.kbs.length ? `KBs: ${v.kbs.map((k) => `KB${k.kb}`).join(', ')}` : 'Sem KB associada',
            ].join('\n')
        )
        .join('\n\n');

export { condenseTitle };
