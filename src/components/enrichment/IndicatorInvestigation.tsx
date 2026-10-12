import type { ReactNode } from 'react';
import type { ThreatIntelligenceResult } from '@/types/threat-intelligence';
import { detectAnalyzerQueryType } from '@/utils/iocExtract';
import { parsePublicCidr } from '@/utils/networkInvestigation';
import { CidrInvestigation } from './CidrInvestigation';
import { DomainInvestigation } from './DomainInvestigation';

export function IndicatorInvestigation({ data, vendors, pt, onPivot, children }: { data: ThreatIntelligenceResult; vendors: string[]; pt: boolean; onPivot: (value: string) => void; children: ReactNode }) {
  if (parsePublicCidr(data.query)) return <CidrInvestigation query={data.query} vendors={vendors} pt={pt} onPivot={onPivot} />;
  if (detectAnalyzerQueryType(data.query) === 'domain') return <DomainInvestigation data={data} pt={pt} onPivot={onPivot}>{children}</DomainInvestigation>;
  return <>{children}</>;
}
