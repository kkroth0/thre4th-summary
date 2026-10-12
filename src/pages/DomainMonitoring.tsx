import { useSearchParams } from 'react-router-dom';
import { PageLayout } from '@/components/PageLayout';
import { BrandHunt } from '@/components/phishing/BrandHunt';
import { PhishTickets } from '@/components/phishing/PhishTickets';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useLanguage } from '@/contexts/LanguageContext';

export default function DomainMonitoring() {
  const { language } = useLanguage(); const pt = language === 'pt';
  const [params, setParams] = useSearchParams(); const view = params.get('view') === 'tickets' ? 'tickets' : 'hunt';
  const change = (value: string) => setParams(previous => { const next = new URLSearchParams(previous); next.set('view', value); return next; });
  return <PageLayout width="max-w-[1600px]" breadcrumbItems={[{ label: view === 'tickets' ? 'Tickets' : pt ? 'Caça a domínios' : 'Domain hunting' }]}>
    <header className="mb-6"><h1 className="page-title">{pt ? 'Monitoramento de domínios' : 'Domain monitoring'}</h1><p className="page-lede">{pt ? 'Acompanhe domínios associados às marcas da organização, revise evidências e gerencie os tickets.' : 'Monitor domains associated with organization brands, review evidence and manage tickets.'}</p></header>
    <Tabs value={view} onValueChange={change}><TabsList variant="underline" className="mb-5"><TabsTrigger value="hunt">{pt ? 'Caça a domínios' : 'Domain hunting'}</TabsTrigger><TabsTrigger value="tickets">Tickets</TabsTrigger></TabsList><TabsContent value="hunt"><BrandHunt /></TabsContent><TabsContent value="tickets"><PhishTickets /></TabsContent></Tabs>
  </PageLayout>;
}
