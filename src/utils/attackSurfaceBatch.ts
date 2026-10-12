import type { AttackSurfaceFinding, AttackSurfaceResponse, AttackSurfaceRisk } from "@/services/threatApi";

const riskOrder: Record<AttackSurfaceRisk, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const findingKey = ({ ip, port, transport }: AttackSurfaceFinding) => `${ip}:${port}/${transport}`;

// Só chave inválida (401), acesso negado (403) e crédito zerado abortam o lote:
// todo alvo seguinte falharia igual. 429 não entra — o gate do servidor já
// reespaça e repete, então um 429 que escapou é transitório e custa só o alvo
// dele. E 404 é "o Shodan não conhece esse IP", que nem erro é.
export const abortsBatch = (message: string) =>
  /\b(401|403)\b/.test(message) || /credit/i.test(message);

export const mergeAttackSurfaceResponses = (responses: AttackSurfaceResponse[]): AttackSurfaceResponse | null => {
  const latest = responses.at(-1);
  if (!latest) return null;

  const seen = new Map<string, AttackSurfaceFinding>();
  const warnings = new Set<string>();
  const providers = { shodan: false };
  let totalObserved = 0;

  for (const response of responses) {
    totalObserved += response.summary.totalObserved;
    response.warnings.forEach((warning) => warnings.add(warning));
    providers.shodan ||= response.summary.providers.shodan;
    // Shodan mostra lookup de host como `ip:x.x.x.x`; a busca já vem formatada.
    const sourceQuery = response.queryKind === "host" ? `ip:${response.query}` : response.query;
    response.findings.forEach((item) => {
      const key = findingKey(item);
      if (!seen.has(key)) seen.set(key, { ...item, sourceQuery });
    });
  }

  const findings = [...seen.values()]
    .sort((a, b) => riskOrder[b.risk] - riskOrder[a.risk] || b.riskScore - a.riskScore || a.ip.localeCompare(b.ip) || a.port - b.port)
    .map((item, index) => ({ ...item, id: `${findingKey(item)}:${index}` }));
  const byRisk = findings.reduce<Record<AttackSurfaceRisk, number>>(
    (counts, item) => ({ ...counts, [item.risk]: counts[item.risk] + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0 },
  );

  return {
    ...latest,
    query: `Batch: ${responses.length} request(s)`,
    findings,
    warnings: [...warnings],
    summary: {
      totalAssets: new Set(findings.map((item) => item.ip)).size,
      totalServices: findings.length,
      criticalHighFindings: byRisk.critical + byRisk.high,
      activelyConfirmedOpen: findings.filter((item) => item.validation.status === "open").length,
      byRisk,
      providers: providers,
      warnings: [...warnings],
      totalObserved,
    },
  };
};
