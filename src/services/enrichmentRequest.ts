/** Passive lookups only: bounded retries honour provider cooldowns. Never rotate here. */
export class EnrichmentRequestError extends Error {
  constructor(message: string, public status: number, public retryAt?: number, public code?: string) { super(message); }
}
const sharedCooldowns = new Map<string, EnrichmentRequestError>();
export const enrichmentRetryAt = (response: Response, now: number): number | undefined => {
  const value = response.headers.get('Retry-After');
  if (value == null) return undefined;
  const seconds = Number(value);
  const at = Number.isFinite(seconds) ? now + Math.max(0, seconds) * 1000 : Date.parse(value);
  return Number.isFinite(at) ? at : undefined;
};
export async function enrichmentRequest(url: string, init: RequestInit, options: {
  fetch?: typeof fetch; now?: () => number; sleep?: (ms: number) => Promise<void>;
  onWait?: (at: number) => void; budgetMs?: number; timeoutMs?: number;
  cooldowns?: Map<string, EnrichmentRequestError>;
} = {}): Promise<Response> {
  const request = options.fetch || fetch, now = options.now || Date.now;
  const sleep = options.sleep || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const deadline = now() + (options.budgetMs ?? 75000);
  const cooldowns = options.cooldowns || sharedCooldowns;
  const blocked = cooldowns.get(url);
  if (blocked?.retryAt > now()) throw blocked;
  cooldowns.delete(url);
  let last: EnrichmentRequestError | undefined;
  for (let attempt = 0; attempt < 30; attempt++) {
    if (init.signal?.aborted) throw new EnrichmentRequestError('Consulta interrompida.', 0);
    const remaining = deadline - now();
    if (remaining <= 0) break;
    const controller = new AbortController();
    const abort = () => controller.abort();
    init.signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, Math.min(options.timeoutMs ?? 20000, remaining));
    let at: number | undefined;
    try {
      const response = await request(url, { ...init, signal: controller.signal });
      if (response.ok || ![429, 502, 503, 504].includes(response.status)) return response;
      if (response.headers.get('Content-Type')?.includes('json')) {
        const detail = await response.clone().json().catch(() => null);
        if (detail?.code === 'PROVIDER_AUTH_FAILED' || /authentication|configuration|API Key missing/i.test(String(detail?.error || ''))) {
          const error = new EnrichmentRequestError('A fonte recusou a credencial. Revise a conexão em Chaves de API.', response.status, now() + 600000, 'PROVIDER_AUTH_FAILED');
          cooldowns.set(url, error); await response.body?.cancel(); throw error;
        }
      }
      at = enrichmentRetryAt(response, now());
      // A gateway HTML page must never become a table cell or an exported error.
      await response.body?.cancel();
      last = new EnrichmentRequestError(response.status === 429
        ? 'Fonte aguardando disponibilidade ou renovação da cota.'
        : 'Fonte temporariamente indisponível; consulta pendente.', response.status, at);
    } catch (error) {
      if (error instanceof EnrichmentRequestError && error.code === 'PROVIDER_AUTH_FAILED') throw error;
      if (init.signal?.aborted) throw new EnrichmentRequestError('Consulta interrompida.', 0);
      last = error instanceof EnrichmentRequestError ? error : new EnrichmentRequestError('Falha temporária de conexão; consulta pendente.', 0);
    } finally {
      clearTimeout(timer); init.signal?.removeEventListener('abort', abort);
    }
    const delay = Math.max(1000, at == null ? Math.min(8000, 1000 * 2 ** Math.min(attempt, 3)) : at - now());
    last.retryAt = at ?? now() + delay;
    if (last.status === 429) cooldowns.set(url, last);
    // Long daily/monthly quotas remain explicit pending work, never a success.
    if (attempt === 29 || delay > 20000 || now() + delay >= deadline) throw last;
    options.onWait?.(last.retryAt);
    await sleep(delay);
  }
  throw last || new EnrichmentRequestError('Tempo de consulta excedido; consulta pendente.', 0);
}
