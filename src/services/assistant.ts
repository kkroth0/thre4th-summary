export interface TelegramStatus {
  configured: boolean; connected: boolean; username: string | null;
  aiEnabled: boolean; aiAvailable: boolean; encryptionAvailable?: boolean;
  webhookAvailable: boolean;
  dailyEnabled: boolean; dailyHour: number; timeZone: string; accessAllowed: boolean;
  limits: { hourlyQueries: number; dailyAi: number; linkMinutes: number };
  aiUsedToday: number;
  deliveries: { state: string; created: number; aiUsed: number; messageId: string | null; error: string | null }[];
}
export interface AssistantAnswer { text: string; aiUsed: boolean; aiFallback?: boolean; cacheHit?: boolean }
async function request<T>(url: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch(url, { method, credentials: 'same-origin', headers: body === undefined ? undefined : { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || 'Não foi possível concluir a operação.');
  return value;
}
const base = '/api/integrations/telegram';
export const fetchTelegramStatus = () => request<TelegramStatus>(base);
export const connectTelegram = (token: string) => request<TelegramStatus>(base + '/connect', 'POST', { token });
export const createTelegramLink = () => request<{ url: string; expiresAt: string }>(base + '/link', 'POST', {});
export const updateTelegram = (value: { aiEnabled: boolean; dailyEnabled: boolean; dailyHour: number }) => request<TelegramStatus>(base, 'PATCH', value);
export const disconnectTelegram = () => request<TelegramStatus>(base, 'DELETE');
export const queryAssistant = (question: string, aiEnabled: boolean) => request<AssistantAnswer>('/api/assistant/query', 'POST', { question, aiEnabled });
