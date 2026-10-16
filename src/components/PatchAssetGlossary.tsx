import { useMemo, useState } from 'react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import type { OtPatchData } from '@/services/otPatchApi';

export function PatchAssetGlossary({ data, ai, pt }: { data: OtPatchData | null; ai: boolean; pt: boolean }) {
  const [search, setSearch] = useState(''), [category, setCategory] = useState('all');
  const categories = [...new Set(data?.catalog.map(t => t.category).filter(Boolean) || [])];
  const tools = useMemo(() => (data?.catalog || []).filter(t => (category === 'all' || t.category === category) && `${t.vendor} ${t.category} ${t.description} ${t.models.join(' ')}`.toLowerCase().includes(search.toLowerCase())), [data, category, search]);
  const equipment = (data?.equipmentTypes || []).filter(t => `${t.name} ${t.nameEn} ${t.description}`.toLowerCase().includes(search.toLowerCase()));
  return <section className="space-y-4">
    <div><h2 className="text-lg font-semibold">{pt ? 'Glossário de Ativos' : 'Asset glossary'}</h2><p className="mt-1 text-sm text-muted-foreground">{ai ? (pt ? 'Conheça a função de cada ferramenta e encontre os pacotes usados para reconhecer seus avisos de segurança.' : 'Learn what each tool does and which packages identify its security advisories.') : (pt ? 'Conheça os equipamentos industriais e os cuidados ao planejar uma atualização.' : 'Learn about industrial equipment and what to check before an update.')}</p></div>
    <Input className="max-w-xl" aria-label={pt ? 'Buscar no glossário' : 'Search glossary'} placeholder={ai ? (pt ? 'Ferramenta, categoria ou função…' : 'Tool, category or purpose…') : (pt ? 'Tipo de equipamento ou função…' : 'Equipment type or purpose…')} value={search} onChange={e => setSearch(e.target.value)} />
    {ai && <div className="flex flex-wrap gap-2"><Button size="sm" variant={category === 'all' ? 'default' : 'outline'} onClick={() => setCategory('all')}>{pt ? 'Todas' : 'All'}</Button>{categories.map(c => <Button key={c} size="sm" variant={category === c ? 'default' : 'outline'} onClick={() => setCategory(c!)}>{c}</Button>)}</div>}
    <p className="text-xs text-muted-foreground">{ai ? tools.length : equipment.length} {pt ? 'itens encontrados' : 'items found'}</p>
    <div className="grid gap-3 md:grid-cols-2">{ai ? tools.map(t => <article key={t.vendor} className="rounded-lg border bg-card p-4"><h3 className="font-semibold">{t.vendor}</h3>{t.category && <Badge variant="outline" className="mt-2 text-[10px]">{t.category}</Badge>}<p className="mt-3 text-sm text-muted-foreground">{(pt ? t.description : t.descriptionEn) || (pt ? 'Componente identificado em um aviso público. Consulte a documentação do pacote para conhecer sua função e aplicação.' : 'Component identified in a public advisory. Check the package documentation for its purpose and use.')}</p>{!!t.models.length && <p className="mt-3 break-words text-xs text-muted-foreground">{pt ? 'Pacotes de referência' : 'Reference packages'}: {t.models.join(' · ')}</p>}{t.url && <a href={t.url} target="_blank" rel="noreferrer" className="mt-3 inline-block text-xs text-primary underline">{pt ? 'Documentação e projeto oficial' : 'Official project and documentation'}</a>}</article>) : equipment.map(t => <article key={t.id} className="rounded-lg border bg-card p-4"><h3 className="font-semibold">{pt ? t.name : t.nameEn}</h3><p className="mt-2 text-sm text-muted-foreground">{pt ? t.description : t.descriptionEn}</p>{pt && <p className="mt-3 text-xs text-muted-foreground"><strong>Na atualização:</strong> {t.patchContext}</p>}</article>)}</div>
    {!ai && data?.equipmentReference && <a href={data.equipmentReference} target="_blank" rel="noreferrer" className="text-xs text-primary underline">{pt ? 'Referência: guia de segurança OT do NIST' : 'Reference: NIST OT security guide'}</a>}
  </section>;
}
