import test from 'node:test';
import assert from 'node:assert/strict';
import type { WeeklyReportData } from '@/types/weekly-report';
import { buildThreatSumm4ryWeeklySlides, weeklyBrandFilename, WEEKLY_BRAND } from './weeklyThreatSumm4ry';

export const brandReport: WeeklyReportData = {
  range: { id: '2026-10-17', from: '2026-10-17T03:00:00Z', to: '2026-10-24T03:00:00Z', timezone: 'America/Fortaleza', exclusiveEnd: true },
  scope: 'global', profile: null,
  generatedAt: '2026-10-24T03:00:00Z', updatedAt: '2026-10-24T03:00:00Z', revision: 1,
  news: [{ id: 'demo-news', title: 'Matéria demonstrativa', summary: 'Resumo do feed não deve ser exportado.', published: '2026-10-22T15:30:00Z', publicationTimeKnown: true, score: 85, severity: 'High', categories: [], actors: [], malware: [], cves: [], ttps: [], sources: [{ title: 'Relatório de demonstração', source: 'Fonte demonstrativa', link: 'https://example.com/research', published: '2026-10-22T15:30:00Z' }] }],
  aiNews: [], candidates: { news: [], aiNews: [] }, selection: { mode: 'manual', newsIds: ['demo-news'], aiNewsIds: [] },
  vulnerabilities: { total: 4606, critical: 20, kevCount: 7, kev: [], priority: [{ id: 'CVE-2026-12345', product: 'Produto demonstrativo', vendor: 'Fabricante demonstrativo', description: 'Descrição de exemplo para conferir a apresentação. Não representa uma vulnerabilidade real.', cvss: 9.1, severity: 'CRITICAL', published: '2026-10-20', dateAdded: '', kev: false, epss: null, action: 'A versão corrigida deve seguir a referência do fabricante, considerando a exposição e a janela operacional.', references: [{ url: 'https://example.com/advisory' }] }], monitored: [], ai: { total: 2, critical: 1, items: [], vendors: [] } },
  ransomware: { total: 10, latam: 10, brazil: 3, victims: [{ id: 'victim', name: 'Organização fictícia', group: 'Grupo demonstrativo', sector: 'Manufacturing', country: 'BR', published: '2026-10-22', discovered: '2026-10-22', permalink: 'https://example.com/claim', description: '', claimStatus: 'unconfirmed' }], byCountry: [{ name: 'BR', count: 3 }], byGroup: [], bySector: [{ name: 'Manufacturing', count: 4 }, { name: 'Healthcare', count: 6 }], focusSectors: ['Manufacturing'], claimsAreUnconfirmed: true },
  reports: [], recommendations: [], actors: [], malware: [], ttps: [], sources: [{ title: 'Relatório demonstrativo', source: 'Fonte demonstrativa', link: 'https://example.com/research', published: '2026-10-22' }],
  coverage: { news: { publications: 120, lastCollectedAt: '2026-10-24T03:00:00Z' }, ransomware: { status: 'ready' }, vulnerabilities: { status: 'ready', sources: { nvd: { status: 'ready' }, kev: { status: 'ready' } } } },
  editorial: { status: 'ready', available: true, articles: [{ id: 'demo-news', status: 'ready', title: 'Acesso de terceiros amplia o alcance de um comprometimento', lead: 'Este conteúdo é uma demonstração visual. O cenário ilustra como uma credencial de integração pode alcançar diferentes sistemas quando as permissões ultrapassam a necessidade do serviço.', context: 'O impacto depende das integrações ativas e dos privilégios da conta. O cenário não indica comprometimento da qualquer organização específica.', body: ['Em uma investigação, o acesso inicial e as permissões obtidas explicam o alcance da atividade. Contas usadas em integrações podem conectar serviços de nuvem e sistemas internos, criando caminhos que precisam ser considerados na análise.', 'A leitura executiva reúne os fatos reportados e suas consequências possíveis. A existência de uma integração, isoladamente, não confirma exposição: essa relação depende do inventário, das permissões e dos registros disponíveis.'], attention: [{ title: 'Integrações com acesso amplo', text: 'Uma credencial pode alcançar mais de um sistema. O escopo das permissões determina o limite potencial da atividade.' }, { title: 'Dependências operacionais', text: 'A suspensão de uma integração pode afetar processos essenciais. O contexto da operação faz parte da avaliação.' }, { title: 'Registros de autenticação', text: 'A origem das sessões e as alterações de privilégios ajudam a delimitar a atividade observada no período.' }], sourceUrls: ['https://example.com/research'], evidence: [{ url: 'https://example.com/research', status: 'read', hash: 'demo-evidence' }] }], sections: { executive: { priority: 'Exemplo visual: acessos de terceiros e continuidade operacional', overview: 'Esta edição demonstrativa apresenta a nova identidade do boletim ThreatSumm4ry. Notícias selecionadas pelo analista aparecem com contexto executivo, desenvolvimento e referências às fontes.\n\nOs números desta demonstração servem apenas para validar o design. A edição gerada pela plataforma usa os dados do período e da cobertura mundial, preservando a separação entre fatos reportados, alegações e possibilidades.' }, ransomware: { overview: 'Dados demonstrativos. As publicações de grupos de ransomware são alegações e não representam confirmação independente de incidentes.', trend: 'A evolução deve considerar períodos com cobertura comparável. Uma semana parcial não sustenta a conclusão de redução dos ataques.', groups: 'O volume de publicações não demonstra, isoladamente, a capacidade operacional de um grupo.' }, ai: { interpretation: 'O acompanhamento considera vulnerabilidades em ferramentas de IA, agentes e integrações.', leadership: 'O contexto depende do uso das ferramentas e do acesso a dados e sistemas.' }, cves: [] } },
};

test('global filename never identifies a recipient', () => {
  assert.match(weeklyBrandFilename(brandReport), /^ThreatSumm4ry_Boletim_Global_/);
  assert.equal(WEEKLY_BRAND.format, 'A4 portrait');
});
test('global publication uses original page models and complete sourced articles', () => {
  const pages = buildThreatSumm4ryWeeklySlides(brandReport);
  const story = pages.find(p => p.kind === 'article')!;
  assert.deepEqual(story.article?.body, brandReport.editorial!.articles![0].body);
  assert.equal(story.article?.sourceUrls?.[0], 'https://example.com/research');
  assert.ok(pages.some(p => p.kind === 'ransomware'));
  assert.ok(pages.some(p => p.kind === 'sources'));
  assert.ok(pages.every(p => !('source' in p)));
});
test('client drafts and incomplete source-based writing cannot become global editions', () => {
  assert.throws(() => buildThreatSumm4ryWeeklySlides({...brandReport, scope:'organization', profile:{id:'client',name:'Client'}}), /global/);
  assert.throws(() => buildThreatSumm4ryWeeklySlides({...brandReport, editorial:{status:'partial',available:true}}), /Redija/);
  assert.throws(() => buildThreatSumm4ryWeeklySlides({...brandReport, editorial:{...brandReport.editorial!,articles:[]}}), /matérias/);
});

test('magazine retains developed paragraphs, includes sector detail and omits empty CVE spreads',()=>{
 const original=brandReport.editorial!.articles![0];
 const report={...brandReport,editorial:{...brandReport.editorial!,articles:[{...original,body:[...original.body!,'Terceiro parágrafo com contexto sustentado.','Quarto parágrafo com os limites da análise.']}]}};
 const pages=buildThreatSumm4ryWeeklySlides(report);
 assert.equal(pages.find(p=>p.kind==='article')!.article!.body!.length,4);
 assert.ok(pages.some(p=>p.kind==='sectors'));
 assert.ok(pages.some(p=>p.kind==='victims'));
 assert.ok(pages.some(p=>p.kind==='method'));
 assert.ok(pages.filter(p=>p.kind==='cves').every(p=>p.cves!.length));
 const sectors=Array.from({length:27},(_,i)=>({name:'Sector '+i,count:i+1}));
 const full=buildThreatSumm4ryWeeklySlides({...report,ransomware:{...report.ransomware,bySector:sectors}});
 assert.deepEqual(full.filter(p=>p.kind==='sectors').map(p=>p.offset),[0,14]);
});
