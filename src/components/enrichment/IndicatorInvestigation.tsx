import type { ReactNode } from 'react';
import type { ThreatIntelligenceResult } from '@/types/threat-intelligence';
import { investigationDomain } from '@/utils/domainInvestigation';
import { parsePublicCidr } from '@/utils/networkInvestigation';
import { CidrInvestigation } from './CidrInvestigation';
import { DomainWorkspace } from './DomainWorkspace';

export function IndicatorInvestigation({ data, vendors, pt, onPivot, children }: { data: ThreatIntelligenceResult; vendors: string[]; pt: boolean; onPivot: (value: string) => void; children: ReactNode }) {
  if (parsePublicCidr(data.query)) return <CidrInvestigation query={data.query} vendors={vendors} pt={pt} onPivot={onPivot} />;
  const domain = investigationDomain(data.query);
  if (domain) return <DomainWorkspace key={domain} domain={domain} data={data} pt={pt} onPivot={onPivot}>{children}</DomainWorkspace>;
  return <>{children}</>;
}
