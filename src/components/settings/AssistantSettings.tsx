import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Bot, CheckCircle2, Clock3, ExternalLink, Loader2, RefreshCw, Send, Unplug } from 'lucide-react';
import { toast } from 'sonner';
import { useLanguage } from '@/contexts/LanguageContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { connectTelegram, createTelegramLink, disconnectTelegram, fetchTelegramStatus, queryAssistant, updateTelegram, type AssistantAnswer } from '@/services/assistant';

export function AssistantSettings() {
  const { language } = useLanguage(), pt = language === 'pt';
  const [token, setToken] = useState(''), [busy, setBusy] = useState('');
  const [link, setLink] = useState<{ url: string; expiresAt: string } | null>(null);
  const [question, setQuestion] = useState('/briefing'), [previewAi, setPreviewAi] = useState(false), [reply, setReply] = useState<AssistantAnswer | null>(null);
  const [ai, setAi] = useState(false), [daily, setDaily] = useState(false), [hour, setHour] = useState(8);
  const status = useQuery({ queryKey: ['telegram-settings'], queryFn: fetchTelegramStatus, staleTime: 30000, refetchInterval: link ? 5000 : false, retry: false });
  const data = status.data;
  const serverAi = data?.aiEnabled, serverDaily = data?.dailyEnabled, serverHour = data?.dailyHour;
  useEffect(() => { if (serverAi !== undefined) setAi(serverAi); if (serverDaily !== undefined) setDaily(serverDaily); if (serverHour !== undefined) setHour(serverHour); }, [serverAi, serverDaily, serverHour]);
  useEffect(() => { if (data?.connected) setLink(null); }, [data?.connected]);
  useEffect(() => {
    if (!link) return;
    const timer = window.setTimeout(() => setLink(null), Math.max(0, Date.parse(link.expiresAt) - Date.now()));
    return () => window.clearTimeout(timer);
  }, [link]);
  async function act(name: string, operation: () => Promise<void>) {
    setBusy(name);
    try { await operation(); } catch (error) { toast.error((error as Error).message); } finally { setBusy(''); }
  }
  const labels: Record<string, string> = pt ? { queued: 'Na fila', processing: 'Preparando', sending: 'Enviando', sent: 'Entrega confirmada', failed: 'Falha', uncertain: 'Entrega não confirmada', cancelled: 'Cancelado' }
    : { queued: 'Queued', processing: 'Preparing', sending: 'Sending', sent: 'Delivery confirmed', failed: 'Failed', uncertain: 'Delivery unconfirmed', cancelled: 'Cancelled' };
  return <div className="space-y-5">
    <div>
      <h2 className="flex items-center gap-2 text-base font-semibold"><Bot className="h-5 w-5 text-primary" />{pt ? 'Seu analista no Telegram' : 'Your analyst on Telegram'}</h2>
      <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">{pt ? 'Consulte notícias, IOCs, atores, malwares e CVEs da base unificada. Receba um briefing diário com até quatro notícias priorizadas e referências às fontes.' : 'Query news, IOCs, actors, malware and CVEs from the unified database. Receive a daily briefing with up to four prioritized stories and source references.'}</p>
    </div>
    {status.isError && <p role="alert" className="text-sm text-destructive">{(status.error as Error).message}</p>}
    <Card className="rounded-sm shadow-none">
      <CardHeader className="flex flex-row items-center justify-between border-b border-border px-4 py-3">
        <CardTitle className="text-sm">{pt ? '1. Experimente uma consulta' : '1. Try a query'}</CardTitle>
        <Badge variant="outline">{data?.aiAvailable ? (pt ? 'IA configurada no servidor' : 'AI configured on server') : (pt ? 'Consulta local' : 'Local query')}</Badge>
      </CardHeader>
      <CardContent className="space-y-3 p-4">
        <form className="flex flex-wrap gap-2" onSubmit={event => { event.preventDefault(); void act('query', async () => { setReply(await queryAssistant(question, previewAi)); await status.refetch(); }); }}>
          <Input aria-label={pt ? 'Pergunta ao assistente' : 'Assistant question'} value={question} maxLength={500} onChange={event => setQuestion(event.target.value)} className="min-w-0 flex-1 basis-64" placeholder="/buscar Mirai" />
          <Button disabled={!!busy || !question.trim()} type="submit">{busy === 'query' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}{pt ? 'Consultar' : 'Ask'}</Button>
        </form>
        <div className="flex flex-wrap gap-2">{['/briefing', '/briefing semana', '/buscar Mirai', '/ator Lazarus', '/status'].map(value => <button type="button" key={value} onClick={() => setQuestion(value)} className="rounded border border-border px-2 py-1 font-mono text-xs text-muted-foreground hover:text-foreground">{value}</button>)}</div>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={previewAi} disabled={!data?.aiAvailable} onChange={event => setPreviewAi(event.target.checked)} />{pt ? 'Usar IA nesta síntese' : 'Use AI for this summary'}</label>
        <p className="text-xs leading-relaxed text-muted-foreground">{pt ? 'Com IA, a pergunta e trechos das notícias públicas são enviados ao OpenRouter. Evidências privadas das APIs ficam nas respostas locais. Consultar não dispara novas coletas.' : 'With AI, the question and public news excerpts are sent to OpenRouter. Private API evidence stays in local responses. Queries do not trigger new collection.'}</p>
        {reply && <div className="rounded border border-border bg-secondary/20 p-4" aria-live="polite"><div className="mb-3 text-xs text-muted-foreground">{reply.aiUsed ? (pt ? 'Síntese por IA' : 'AI summary') : (pt ? 'Resposta local' : 'Local response')}{reply.cacheHit && (pt ? ' · cache reutilizado' : ' · cached')}</div><p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{reply.text}</p></div>}
      </CardContent>
    </Card>
    <Card className="rounded-sm shadow-none">
      <CardHeader className="flex flex-row items-center justify-between border-b border-border px-4 py-3"><CardTitle className="text-sm">{pt ? '2. Conecte seu bot' : '2. Connect your bot'}</CardTitle><Badge variant="outline">{data?.connected ? (pt ? 'Vinculado' : 'Linked') : data?.configured ? (pt ? 'Aguardando vínculo' : 'Waiting for link') : (pt ? 'Não configurado' : 'Not configured')}</Badge></CardHeader>
      <CardContent className="space-y-4 p-4">
        <p className="text-sm leading-relaxed text-muted-foreground">{pt ? 'No BotFather, envie /newbot, escolha o nome e um username terminado em bot. Cole aqui o token do bot dedicado ao ThreatSumm4ry; ele será armazenado cifrado na sua conta.' : 'Send /newbot to BotFather, choose a name and a username ending in bot. Paste the token for your dedicated ThreatSumm4ry bot; it will be encrypted in your account.'}</p>
        <a href="https://t.me/BotFather" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-sm text-primary">{pt ? 'Abrir BotFather' : 'Open BotFather'}<ExternalLink className="h-3.5 w-3.5" /></a>
        {!data?.configured && <form className="flex flex-wrap gap-2" onSubmit={event => { event.preventDefault(); void act('connect', async () => { await connectTelegram(token); setToken(''); await status.refetch(); toast.success(pt ? 'Bot configurado. Agora vincule seu Telegram.' : 'Bot configured. Link your Telegram next.'); }); }}>
          <Input type="password" autoComplete="off" aria-label={pt ? 'Token do bot Telegram' : 'Telegram bot token'} value={token} onChange={event => setToken(event.target.value)} placeholder="BotFather token" className="min-w-0 flex-1 basis-64" />
          <Button disabled={!!busy || !token.trim() || data?.encryptionAvailable === false || data?.webhookAvailable === false} type="submit">{busy === 'connect' && <Loader2 className="h-4 w-4 animate-spin" />}{pt ? 'Conectar bot' : 'Connect bot'}</Button>
        </form>}
        {data?.encryptionAvailable === false && <p role="alert" className="text-sm text-destructive">{pt ? 'O armazenamento cifrado precisa ser habilitado no servidor antes de conectar.' : 'Encrypted credential storage must be enabled on the server before connecting.'}</p>}
        {data?.webhookAvailable === false && <p role="alert" className="text-sm text-destructive">{pt ? 'Configure a URL HTTPS pública da plataforma no servidor antes de conectar.' : 'Configure the public HTTPS application URL on the server before connecting.'}</p>}
        {data?.configured && <div className="flex flex-wrap items-center gap-2"><span className="mr-auto font-mono text-sm">@{data.username}</span>
          <Button variant="outline" disabled={!!busy} onClick={() => void act('link', async () => { setLink(await createTelegramLink()); })}>{pt ? (data.connected ? 'Vincular outra conversa' : 'Vincular meu Telegram') : 'Link my Telegram'}</Button>
          <Button variant="ghost" disabled={!!busy} onClick={() => void act('disconnect', async () => { await disconnectTelegram(); setLink(null); await status.refetch(); })}><Unplug className="h-4 w-4" />{pt ? 'Desconectar' : 'Disconnect'}</Button>
        </div>}
        {link && <div className="rounded border border-primary/25 bg-primary/5 p-3 text-sm"><a className="inline-flex items-center gap-2 font-medium text-primary" href={link.url} target="_blank" rel="noreferrer">{pt ? 'Abrir o bot e tocar em Iniciar' : 'Open bot and tap Start'}<ExternalLink className="h-4 w-4" /></a><p className="mt-1 text-xs text-muted-foreground">{pt ? 'Vínculo de uso único, válido por dez minutos. Use uma conversa privada.' : 'Single-use link, valid for ten minutes. Use a private conversation.'}</p></div>}
        {data?.connected && <p className="flex items-center gap-2 text-sm text-emerald-500"><CheckCircle2 className="h-4 w-4" />{pt ? 'Conversa privada vinculada. Envie /ajuda ao seu bot.' : 'Private conversation linked. Send /ajuda to your bot.'}</p>}
        {data?.configured && !data.accessAllowed && <p role="alert" className="text-sm text-destructive">{pt ? 'Acesso premium precisa ser renovado para o bot continuar respondendo.' : 'Premium access must be renewed for the bot to keep responding.'}</p>}
      </CardContent>
    </Card>
    <Card className="rounded-sm shadow-none">
      <CardHeader className="border-b border-border px-4 py-3"><CardTitle className="flex items-center gap-2 text-sm"><Clock3 className="h-4 w-4" />{pt ? '3. Briefing automático' : '3. Automatic briefing'}</CardTitle></CardHeader>
      <CardContent className="space-y-4 p-4">
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={daily} disabled={!data?.configured || !!busy} onChange={event => setDaily(event.target.checked)} /><span>{pt ? 'Enviar automaticamente um briefing diário para minha conversa vinculada.' : 'Automatically send a daily briefing to my linked conversation.'}</span></label>
        <div className="flex flex-wrap items-center gap-3"><label className="text-sm" htmlFor="telegram-hour">{pt ? 'Horário de Fortaleza' : 'Fortaleza time'}</label><select id="telegram-hour" value={hour} disabled={!data?.configured || !!busy} onChange={event => setHour(Number(event.target.value))} className="rounded border border-border bg-background px-3 py-2 text-sm">{Array.from({ length: 24 }, (_, i) => <option key={i} value={i}>{String(i).padStart(2, '0')}:00</option>)}</select></div>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={ai} disabled={!data?.configured || !data.aiAvailable || !!busy} onChange={event => setAi(event.target.checked)} />{pt ? 'Usar IA nas notícias e briefings do Telegram' : 'Use AI for Telegram news and briefings'}</label>
        <p className="text-xs leading-relaxed text-muted-foreground">{pt ? 'Seleção por criticidade, KEV e data de publicação, com deduplicação por evento e tema. Páginas sem data confirmada ficam na pesquisa. O envio roda na VPS, mesmo com o navegador fechado. A IA recebe apenas a pergunta e evidências públicas; consultas a IOCs e perfis usam os dados locais da sua conta.' : 'Selection uses severity, KEV and publication date, deduplicated by event and topic. Undated pages remain searchable. Delivery runs on the VPS even when your browser is closed. AI receives only the question and public evidence; IOC and profile queries use your account’s local data.'}</p>
        <Button disabled={!data?.configured || !!busy} onClick={() => void act('save', async () => { await updateTelegram({ aiEnabled: ai, dailyEnabled: daily, dailyHour: hour }); await status.refetch(); toast.success(pt ? 'Preferências de entrega salvas' : 'Delivery preferences saved'); })}>{busy === 'save' && <Loader2 className="h-4 w-4 animate-spin" />}{pt ? 'Salvar preferências de entrega' : 'Save delivery preferences'}</Button>
      </CardContent>
    </Card>
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground"><p>{data ? (pt ? 'IA: ' + data.aiUsedToday + '/' + data.limits.dailyAi + ' chamadas hoje · até ' + data.limits.hourlyQueries + ' consultas por hora no bot.' : 'AI: ' + data.aiUsedToday + '/' + data.limits.dailyAi + ' calls today · up to ' + data.limits.hourlyQueries + ' bot queries per hour.') : ''}</p><Button size="sm" variant="ghost" disabled={status.isFetching} onClick={() => void status.refetch()}><RefreshCw className="h-3 w-3" />{pt ? 'Verificar conexão' : 'Check connection'}</Button></div>
    {!!data?.deliveries.length && <div className="rounded border border-border p-4"><h3 className="mb-3 text-sm font-medium">{pt ? 'Entregas recentes' : 'Recent deliveries'}</h3><ul className="divide-y divide-border/50">{data.deliveries.map((item, i) => <li key={i} className="flex justify-between gap-3 py-2 text-xs"><span>{new Date(item.created).toLocaleString(pt ? 'pt-BR' : 'en-GB', { timeZone: 'America/Fortaleza' })}</span><span>{labels[item.state] || item.state}{!!item.aiUsed && ' · IA'}</span></li>)}</ul><p className="mt-3 text-xs text-muted-foreground">{pt ? 'Entregas sem confirmação não são reenviadas automaticamente para evitar duplicatas.' : 'Unconfirmed deliveries are not automatically resent to avoid duplicates.'}</p></div>}
  </div>;
}
