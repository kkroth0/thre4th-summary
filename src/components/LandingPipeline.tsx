import { Network, Rss, Search } from 'lucide-react';

export function LandingPipeline({ pt }: { pt: boolean }) {
  const stages = [
    { icon: Rss, title: pt ? 'Reúna as fontes' : 'Collect your sources', text: pt ? 'Notícias, advisories e pesquisas, com bases de enriquecimento para aprofundar a investigação.' : 'News, advisories and research, with enrichment sources for deeper investigation.', items: ['CISA', 'NVD', 'MSRC', 'abuse.ch'] },
    { icon: Network, title: pt ? 'Conecte as evidências' : 'Connect the evidence', text: pt ? 'CVEs, IOCs e menções a atores, malware e técnicas, organizados por publicação e evento.' : 'CVEs, IOCs and mentions of actors, malware and techniques, organized by publication and event.', items: ['CVE', 'IOC', pt ? 'Ator' : 'Actor', 'Malware', 'TTP'] },
    { icon: Search, title: pt ? 'Aprofunde a investigação' : 'Investigate further', text: pt ? 'Parta das notícias para explorar indicadores, perfis e campanhas, mantendo a fonte original por perto.' : 'Start from news to explore indicators, profiles and campaigns, with original sources close at hand.', items: [pt ? 'Notícias e IOCs' : 'News & IOCs', pt ? 'Enriquecimento' : 'Enrichment', 'Phishing', pt ? 'Relatórios' : 'Reports'] },
  ];
  return (
    <section aria-labelledby="pipeline-title" className="border-t border-border py-12 md:py-16">
      <header className="mb-7 max-w-3xl">
        <p className="mb-2 text-xs font-semibold uppercase tracking-widest text-primary">{pt ? 'Como funciona' : 'How it works'}</p>
        <h2 id="pipeline-title" className="text-2xl font-semibold tracking-tight sm:text-3xl">{pt ? 'Fontes. Evidências. Investigação.' : 'Sources. Evidence. Investigation.'}</h2>
        <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{pt ? 'Uma publicação é o começo. O ThreatSumm4ry reúne o contexto extraído e a cobertura do evento para orientar sua pesquisa.' : 'A publication is the starting point. ThreatSumm4ry brings extracted context and event coverage together to guide your research.'}</p>
      </header>
      <figure className="overflow-hidden rounded-xl border border-border">
        <picture className="hidden bg-[#0d1117] md:block">
          <source media="(min-width: 768px)" srcSet={pt ? '/images/etl-pipeline-pt-v1.png' : '/images/etl-pipeline-en-v1.png'} />
          <img src="/threatsumm4ry-mark.svg" width={pt ? 1942 : 1944} height={809} loading="lazy" decoding="async" className="block h-auto w-full" alt={pt ? 'Fluxo CTI: fontes convergem para coleta e extração, evidências de um evento se conectam a CVEs, IOCs, atores, malware, técnicas e fonte original, e alimentam as ferramentas de investigação.' : 'CTI workflow: sources converge into collection and extraction; event evidence connects CVEs, IOCs, actors, malware, techniques and original sources to investigation tools.'} />
        </picture>
        <div className="grid divide-y divide-border bg-card md:grid-cols-3 md:divide-x md:divide-y-0">
          {stages.map(({ icon: Icon, title, text, items }, index) => (
            <div key={title} className="p-5 md:p-6">
              <div className="mb-3 flex items-center gap-2 text-sm font-semibold"><Icon className="h-4 w-4 shrink-0 text-primary" /><span className="font-mono text-xs text-muted-foreground">0{index + 1}</span><h3>{title}</h3></div>
              <p className="text-sm leading-relaxed text-muted-foreground">{text}</p>
              <div className="mt-4 flex flex-wrap gap-1.5 md:hidden">{items.map(item => <span key={item} className="rounded border border-border px-2 py-1 text-[11px] text-muted-foreground">{item}</span>)}</div>
            </div>
          ))}
        </div>
        <figcaption className="border-t border-border bg-background px-5 py-3 text-xs leading-relaxed text-muted-foreground">{pt ? 'Fluxo ilustrativo. As relações são baseadas nas evidências disponíveis; as publicações originais permanecem acessíveis para revisão.' : 'Illustrative workflow. Relationships depend on available evidence; original publications remain accessible for review.'}</figcaption>
      </figure>
    </section>
  );
}
