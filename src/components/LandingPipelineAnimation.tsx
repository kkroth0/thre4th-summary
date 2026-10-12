import { useEffect, useRef, useState } from 'react';
import { Download, Pause, Play } from 'lucide-react';
import { PIPELINE_CYCLE, pipelineFlows, pipelinePulses, pipelineSvgPath } from '@/lib/landingPipelineMotion';

export function LandingPipelineAnimation({ pt }: { pt: boolean }) {
  const svg = useRef<SVGSVGElement>(null);
  const viewport = useRef<HTMLDivElement>(null);
  // The system preference sets the default; an explicit Play click opts in.
  const [paused, setPaused] = useState<boolean | null>(null);
  const [reducedMotion, setReducedMotion] = useState(true);
  const [visible, setVisible] = useState(false);
  const [pageVisible, setPageVisible] = useState(true);
  const stopped = paused ?? reducedMotion;

  useEffect(() => {
    const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
    const syncPreference = () => setReducedMotion(preference.matches);
    const syncVisibility = () => setPageVisible(!document.hidden);
    const observer = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting));
    if (viewport.current) observer.observe(viewport.current);
    syncPreference();
    syncVisibility();
    preference.addEventListener('change', syncPreference);
    document.addEventListener('visibilitychange', syncVisibility);
    return () => {
      observer.disconnect();
      preference.removeEventListener('change', syncPreference);
      document.removeEventListener('visibilitychange', syncVisibility);
    };
  }, []);

  useEffect(() => {
    if (stopped || !visible || !pageVisible) svg.current?.pauseAnimations();
    else svg.current?.unpauseAnimations();
  }, [stopped, visible, pageVisible]);

  const fraction = (seconds: number) => (seconds / PIPELINE_CYCLE).toFixed(5);
  return (
    <>
      <div ref={viewport} className="relative hidden bg-[#0d1117] md:block">
        <picture>
          <source srcSet={pt ? '/images/etl-pipeline-pt-v1.png' : '/images/etl-pipeline-en-v1.png'} media="(min-width: 768px)" />
          <img src="/threatsumm4ry-mark.svg" width={pt ? 1942 : 1944} height={809} loading="lazy" decoding="async" className="block h-auto w-full" alt={pt ? 'Fluxo CTI: fontes convergem para coleta e extração; um evento conecta CVEs, IOCs, atores, malware, técnicas e fonte original às ferramentas de investigação.' : 'CTI workflow: sources converge into collection and extraction; an event connects CVEs, IOCs, actors, malware, techniques and original sources to investigation tools.'} />
        </picture>
        <svg ref={svg} viewBox="0 0 1942 809" aria-hidden="true" data-motion-enabled={stopped ? undefined : 'true'} className="pipeline-motion pointer-events-none absolute inset-0 h-full w-full">
          <g>
            {pipelineFlows.map(flow => (
              <g key={flow.id} opacity="0">
                <animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes={`0;${fraction(flow.start)};${fraction(flow.start + 0.06)};${fraction(flow.start + flow.duration - 0.06)};${fraction(flow.start + flow.duration)};1`} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
                <animateMotion path={pipelineSvgPath(flow.curves)} calcMode="linear" keyPoints="0;0;1;1" keyTimes={`0;${fraction(flow.start)};${fraction(flow.start + flow.duration)};1`} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
                <circle r="13" fill="#f97316" opacity="0.18" />
                <circle r="5" fill="#ffcf99" />
              </g>
            ))}
            {pipelinePulses.map(pulse => (
              <rect key={pulse.id} x={pulse.x} y={pulse.y} width={pulse.width} height={pulse.height} rx="10" fill="none" stroke="#fb923c" strokeWidth="3" opacity="0">
                <animate attributeName="opacity" values="0;0;0.7;0;0" keyTimes={`0;${fraction(pulse.start)};${fraction(pulse.start + pulse.duration / 2)};${fraction(pulse.start + pulse.duration)};1`} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
              </rect>
            ))}
          </g>
        </svg>
        <button type="button" onClick={() => setPaused(!stopped)} aria-label={stopped ? (pt ? 'Reproduzir animação do fluxo' : 'Play workflow animation') : (pt ? 'Pausar animação do fluxo' : 'Pause workflow animation')} className="absolute bottom-3 right-3 inline-flex items-center gap-2 rounded-md border border-white/15 bg-[#0d1117]/90 px-3 py-2 text-xs text-white/75 transition-colors hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">
          {stopped ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          {stopped ? (pt ? 'Reproduzir' : 'Play') : (pt ? 'Pausar' : 'Pause')}
        </button>
      </div>
      <a href={pt ? '/images/etl-pipeline-pt-animated-v2.gif' : '/images/etl-pipeline-en-animated-v2.gif'} download className="flex items-center justify-center gap-2 border-t border-border bg-background px-4 py-2 text-xs text-muted-foreground transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary">
        <Download className="h-3.5 w-3.5" />{pt ? 'Baixar diagrama animado · GIF' : 'Download animated diagram · GIF'}
      </a>
    </>
  );
}
