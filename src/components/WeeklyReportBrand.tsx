import type { WeeklyReportData } from '@/types/weekly-report';
import { WEEKLY_BRAND, weeklyBrandPeriod } from '@/utils/weeklyThreatSumm4ry';

export function WeeklyReportBrand({ report }: { report?: WeeklyReportData | null }) {
  return <section aria-label="Boletim global ThreatSumm4ry" className="mb-6 grid overflow-hidden rounded-2xl border border-slate-700/60 bg-[#101b26] text-white lg:grid-cols-[1.25fr_1fr]">
    <div className="relative isolate min-h-[330px] overflow-hidden px-7 py-7 sm:px-9">
      <img src="/templates/weekly-threatsumm4ry/cover-v2.png" alt="" className="absolute inset-0 -z-20 h-full w-full object-cover object-[center_40%] opacity-40" />
      <div className="absolute inset-0 -z-10 bg-gradient-to-r from-[#101b26] via-[#101b26]/70 to-transparent" />
      <img src={WEEKLY_BRAND.logoLight} alt="ThreatSumm4ry" className="h-auto w-44" />
      <p className="mt-9 text-[10px] font-semibold uppercase tracking-[.24em] text-[#ffab66]">Panorama global / Edição semanal</p>
      <h2 className="mt-3 text-4xl font-semibold leading-[1.03] tracking-tight sm:text-5xl">A semana<br />cibernética</h2>
      <p className="mt-5 text-sm text-slate-300">{report ? weeklyBrandPeriod(report) : 'Acontecimentos e conexões ao redor do mundo'}</p>
    </div>
    <div className="flex flex-col justify-center gap-6 border-t border-slate-700/60 p-7 lg:border-l lg:border-t-0 lg:p-9">
      <div><p className="text-xs uppercase tracking-[.16em] text-[#ffab66]">A edição começa aqui</p><p className="mt-3 text-lg leading-7 text-slate-200">Notícias, campanhas e vulnerabilidades conectadas em uma leitura mundial da segurança cibernética.</p></div>
      <div className="grid grid-cols-2 gap-x-5 gap-y-3 border-t border-slate-700 pt-5 text-sm text-slate-300"><span>01 / A leitura da semana</span><span>02 / Notícias e campanhas</span><span>03 / Vulnerabilidades</span><span>04 / Ransomware</span><span>05 / Inteligência artificial</span><span>06 / Fontes e método</span></div>
      <p className="text-xs leading-5 text-slate-400">Escolha as matérias, revise a redação e publique a revista em PowerPoint. Identidade ThreatSumm4ry, com referências clicáveis e gráficos editáveis.</p>
    </div>
  </section>;
}
