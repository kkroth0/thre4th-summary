import type { QueryClient } from '@tanstack/react-query';
import type { AuthState } from '@/services/threatApi';

export const sessionScope = (auth: AuthState) => JSON.stringify(auth.authenticated
  ? [auth.login || '', Boolean(auth.isPremium), Boolean(auth.isAdmin)] : ['anonymous']);

// Destroying queries also cancels in-flight reads, so a late account response
// cannot refill the shared cache after logout or a permission change.
export function resetSessionCache(client: QueryClient, previous: AuthState, next: AuthState) {
  if (sessionScope(previous) !== sessionScope(next)) client.clear();
}
