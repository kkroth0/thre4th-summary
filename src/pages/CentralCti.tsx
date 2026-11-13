import { useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { fetchBoletimDeck, fetchJob, generateBoletim, type BoletimJob } from '@/services/threatApi';
import { parseReportSources } from './dailyBulletinView';

import { CENTRAL_CTI_PENDING, pendingCentralCti } from '@/lib/centralCti';

function readTransfer() {
  const fromApp = window.location.hash.slice(1);
  const params = new URLSearchParams(fromApp || pendingCentralCti());
  const port = Number(params.get('port'));
  const token = params.get('token') || '';
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || !/^[a-f0-9]{64}$/.test(token) || Number(params.get('expires')) <= Date.now()) return null;
  return {
    params,
    endpoint: `http://127.0.0.1:${port}/${token}`,
    sources: params.get('sources') || '',
  };
}

function reportMetadata(job: BoletimJob) {
  const report = job.json;
  const ttps = job.techniques || report?.mitre_ttps?.map(row => row.id) || [];
  const cves = job.cves || [report?.cve_id];
  return {
    id: job.id,
    title: report?.titulo || job.title || 'SRR',
    summary: report?.sumario_executivo || '',
    ttps: [...new Set(ttps.filter(Boolean))].join('; '),
    cves: [...new Set(cves.filter(Boolean))].join('; '),
  };
}

export default function CentralCti() {
  const { auth, loading, loginUrl } = useAuth();
  const [transfer] = useState(readTransfer);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [status, setStatus] = useState('');
  const resumed = useRef(false);
  const inFlight = useRef(false);

  async function send(payload: Record<string, unknown> | Blob) {
    if (!transfer) return;
    const body = payload instanceof Blob ? payload : new Blob([JSON.stringify(payload)], { type: 'application/json' });
    const response = await fetch(transfer.endpoint, {
      method: 'POST', body, credentials: 'omit',
      redirect: 'error', signal: AbortSignal.timeout(30000),
    }).catch(() => { throw new Error('A conexão local falhou. Permita o acesso local no navegador e confira se o Central CTI está aberto.'); });
    if (!response.ok) throw new Error('Esta solicitação expirou. Abra o navegador novamente pelo Central CTI.');
  }

  async function connect() {
    if (!transfer || inFlight.current) return;
    inFlight.current = true;
    setRunning(true);
    setStatus('Conectando ao Central CTI…');
    try {
      if (!auth.authenticated) {
        await send({ state: 'opened' });
        transfer.params.set('resume', '1');
        sessionStorage.setItem(CENTRAL_CTI_PENDING, transfer.params.toString());
        window.location.assign(loginUrl);
        return;
      }
      if (!auth.isPremium || !auth.login) throw new Error('Sua conta precisa ter acesso ao gerador de relatórios.');
      await send({ state: 'connected', login: auth.login });
      if (transfer.sources) {
        try {
          if (!auth.canDownloadReportPdf) throw new Error('Sua conta está conectada, mas precisa de permissão para baixar o PDF do SRR.');
          const { urls, error } = parseReportSources(transfer.sources);
          if (error) throw new Error('Informe até cinco URLs HTTP ou HTTPS no aplicativo.');
          let jobId = transfer.params.get('job');
          if (!jobId) {
            ({ id: jobId } = await generateBoletim(urls, 'auto', '', 'premium'));
            transfer.params.set('job', jobId);
            transfer.params.set('resume', '1');
            sessionStorage.setItem(CENTRAL_CTI_PENDING, transfer.params.toString());
          }
          setStatus('Gerando SRR. Mantenha esta aba aberta até o aplicativo receber o PDF.');
          const deadline = Date.now() + 25 * 60_000;
          let job = await fetchJob(jobId);
          while (job.status === 'pending' && Date.now() < deadline) {
            await new Promise(resolve => setTimeout(resolve, 10000));
            job = await fetchJob(jobId);
          }
          if (job.status !== 'done' || !job.deck?.pdf) throw new Error(job.error || 'O gerador não entregou um PDF para este SRR.');
          const pdf = await fetchBoletimDeck(job, 'pdf');
          await send(new Blob([JSON.stringify(reportMetadata(job)), '\n', pdf], { type: 'application/octet-stream' }));
        } catch (error) {
          const message = (error as Error).message;
          await send({ state: 'error', error: message }).then(() => {
            sessionStorage.removeItem(CENTRAL_CTI_PENDING);
            setDone(true);
          }).catch(() => {});
          throw error;
        }
      }
      sessionStorage.removeItem(CENTRAL_CTI_PENDING);
      setDone(true);
      setStatus(transfer.sources ? 'SRR recebido pelo Central CTI. Volte ao aplicativo para revisar.' : 'Conta conectada. Você já pode voltar ao Central CTI.');
    } catch (error) {
      setStatus((error as Error).message);
    } finally {
      setRunning(false);
      inFlight.current = false;
    }
  }

  useEffect(() => {
    if (transfer && window.location.hash) {
      sessionStorage.setItem(CENTRAL_CTI_PENDING, transfer.params.toString());
      window.history.replaceState(window.history.state, '', window.location.pathname);
    }
    if (loading || !auth.authenticated || resumed.current || transfer?.params.get('resume') !== '1') return;
    resumed.current = true;
    void connect();
  });

  return (
    <main className="min-h-screen px-6 py-16">
      <div className="mx-auto max-w-lg space-y-5 rounded-lg border bg-card p-8">
        <h1 className="text-2xl font-semibold">Central CTI</h1>
        {transfer ? <>
          <p>{transfer.sources ? 'Gere o SRR das fontes abaixo e receba o PDF no aplicativo.' : 'Confirme a conexão da sua conta com o aplicativo.'}</p>
          {transfer.sources && <pre className="whitespace-pre-wrap break-all rounded border p-3 text-sm">{transfer.sources}</pre>}
          <p className="text-sm text-muted-foreground">Se o navegador solicitar acesso ao aplicativo local, permita para que ele receba a atualização.</p>
          <Button disabled={loading || running || done} onClick={() => void connect()}>
            {loading ? 'Verificando sessão…' : !auth.authenticated ? 'Entrar com GitHub' : transfer.sources ? 'Gerar SRR' : 'Conectar ao aplicativo'}
          </Button>
          {status && <p role="status" className="text-sm">{status}</p>}
        </> : <p>Abra esta página pelo aplicativo Central CTI.</p>}
      </div>
    </main>
  );
}
