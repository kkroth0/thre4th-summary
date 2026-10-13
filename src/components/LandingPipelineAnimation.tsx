import { useEffect, useId, useRef, useState } from 'react';
import { Download, Pause, Play } from 'lucide-react';
import { PIPELINE_CYCLE, PIPELINE_PACKET_OFFSETS, pipelineFlows, pipelinePulses, pipelineSvgPath } from '@/lib/landingPipelineMotion';

export function LandingPipelineAnimation({ pt }: { pt: boolean }) {
  const svg = useRef<SVGSVGElement>(null);
  const viewport = useRef<HTMLDivElement>(null);
  // Autoplay is intentional for this product illustration, as requested.
  const [paused, setPaused] = useState(false);
  const [visible, setVisible] = useState(false);
  const [pageVisible, setPageVisible] = useState(true);
  const id = useId().replace(/:/g, '');

  useEffect(() => {
    const syncVisibility = () => setPageVisible(!document.hidden);
    const observer = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting));
    if (viewport.current) observer.observe(viewport.current);
    syncVisibility();
    document.addEventListener('visibilitychange', syncVisibility);
    return () => {
      observer.disconnect();
      document.removeEventListener('visibilitychange', syncVisibility);
    };
  }, []);

  useEffect(() => {
    if (paused || !visible || !pageVisible) svg.current?.pauseAnimations();
    else svg.current?.unpauseAnimations();
  }, [paused, visible, pageVisible]);

  const fraction = (seconds: number) => (seconds / PIPELINE_CYCLE).toFixed(5);
  const timing = (start: number, duration: number) => `0;${fraction(start)};${fraction(start + duration)};1`;
  const envelope = (start: number, duration: number) => `0;${fraction(start)};${fraction(start + 0.06)};${fraction(start + duration - 0.06)};${fraction(start + duration)};1`;
  return (
    <>
      <div ref={viewport} className="relative hidden bg-[#0d1117] md:block">
        <picture>
          <source srcSet={pt ? '/images/etl-pipeline-pt-v1.png' : '/images/etl-pipeline-en-v1.png'} media="(min-width: 768px)" />
          <img src="/threatsumm4ry-mark.svg" width={pt ? 1942 : 1944} height={809} loading="lazy" decoding="async" className="block h-auto w-full" alt={pt ? 'Fluxo CTI: fontes convergem para coleta e extração; um evento conecta CVEs, IOCs, atores, malware, técnicas e fonte original às ferramentas de investigação.' : 'CTI workflow: sources converge into collection and extraction; an event connects CVEs, IOCs, actors, malware, techniques and original sources to investigation tools.'} />
        </picture>
        <svg ref={svg} viewBox="0 0 1942 809" aria-hidden="true" className="pointer-events-none absolute inset-0 h-full w-full">
          <defs>
            <filter id={`${id}-glow`} x="-30%" y="-30%" width="160%" height="160%" colorInterpolationFilters="sRGB">
              <feGaussianBlur stdDeviation="2" /><feMerge><feMergeNode /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            {pipelinePulses.map(pulse => <clipPath key={pulse.id} id={`${id}-${pulse.id}`}><rect x={pulse.x} y={pulse.y} width={pulse.width} height={pulse.height} rx="10" /></clipPath>)}
          </defs>
          <g>
            {pipelineFlows.map(flow => (
              <g key={flow.id} opacity="0">
                <animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes={envelope(flow.start, flow.duration)} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
                {[9, 3.5].map(width => <path key={width} d={pipelineSvgPath(flow.curves)} pathLength="100" fill="none" stroke="#fb923c" strokeWidth={width} strokeOpacity={width === 9 ? 0.18 : 1} strokeLinecap="round" strokeDasharray="15 200" strokeDashoffset="15">
                  <animate attributeName="stroke-dashoffset" values="15;15;-85;-85" keyTimes={timing(flow.start, flow.duration)} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
                </path>)}
              </g>
            ))}
            {pipelineFlows.flatMap(flow => PIPELINE_PACKET_OFFSETS.map((offset, packet) => (
              <g key={`${flow.id}-${packet}`} opacity="0">
                <animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes={envelope(flow.start + offset, flow.duration)} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
                <animateMotion path={pipelineSvgPath(flow.curves)} calcMode="linear" keyPoints="0;0;1;1" keyTimes={timing(flow.start + offset, flow.duration)} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
                <circle r={packet ? 9 : 16} fill="#f97316" opacity={packet ? 0.13 : 0.18} />
                <circle r={packet ? 3 : 5.5} fill={packet ? '#fb923c' : '#ffe4bf'} />
              </g>
            )))}
            {pipelinePulses.map(pulse => (
              <g key={pulse.id} opacity="0">
                <animate attributeName="opacity" values="0;0;1;0;0" keyTimes={`0;${fraction(pulse.start)};${fraction(pulse.start + pulse.duration / 2)};${fraction(pulse.start + pulse.duration)};1`} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
                <rect x={pulse.x} y={pulse.y} width={pulse.width} height={pulse.height} rx="10" fill="#f97316" fillOpacity="0.055" stroke="#fb923c" strokeWidth="2.5" strokeOpacity="0.9" filter={`url(#${id}-glow)`} />
                <g clipPath={`url(#${id}-${pulse.id})`}>
                  <rect x={pulse.x - 50} y={pulse.y} width="45" height={pulse.height} fill="#ffcf99" opacity="0.06">
                    <animate attributeName="x" values={`${pulse.x - 50};${pulse.x - 50};${pulse.x + pulse.width + 50};${pulse.x + pulse.width + 50}`} keyTimes={timing(pulse.start, pulse.duration)} dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
                  </rect>
                </g>
              </g>
            ))}
            <g opacity="0">
              <animate attributeName="opacity" values="0;0;0.9;0;0" keyTimes="0;0.225;0.3;0.45;1" dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
              <circle cx="470" cy="426" r="34" fill="none" stroke="#fb923c" strokeWidth="2" strokeDasharray="28 79" opacity="0.8">
                <animateTransform attributeName="transform" type="rotate" from="0 470 426" to="1440 470 426" dur={`${PIPELINE_CYCLE}s`} repeatCount="indefinite" />
              </circle>
            </g>
          </g>
        </svg>
        <button type="button" onClick={() => setPaused(value => !value)} title={paused ? (pt ? 'Reproduzir animação' : 'Play animation') : (pt ? 'Pausar animação' : 'Pause animation')} aria-label={paused ? (pt ? 'Reproduzir animação do fluxo' : 'Play workflow animation') : (pt ? 'Pausar animação do fluxo' : 'Pause workflow animation')} className="absolute bottom-3 right-3 inline-flex h-8 w-8 items-center justify-center rounded-full border border-white/10 bg-[#0d1117]/80 text-white/60 transition-colors hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">
          {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
        </button>
      </div>
      <a href={pt ? '/images/etl-pipeline-pt-animated-v3.gif' : '/images/etl-pipeline-en-animated-v3.gif'} download className="flex items-center justify-center gap-2 border-t border-border bg-background px-4 py-2 text-xs text-muted-foreground transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary">
        <Download className="h-3.5 w-3.5" />{pt ? 'Baixar diagrama animado · GIF' : 'Download animated diagram · GIF'}
      </a>
    </>
  );
}
