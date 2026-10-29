// Authentication errors must be explicit. A generic 502 can also mean a
// malformed payload, gateway outage or provider-side validation failure.
export function safeUpstreamError(error = {}) {
  const received = Number(error.response?.status) || 500;
  const authentication = Boolean(error.noKey || error.code === 'PROVIDER_AUTH_FAILED' || received === 401 || received === 403);
  const status = authentication ? 502 : received >= 400 && received <= 599 ? received : 500;
  const messages = {
    400: 'Bad request',
    404: 'Resource not found',
    429: 'Rate limit exceeded on upstream provider',
    502: 'Upstream provider returned an invalid or temporarily unavailable response',
    503: 'Upstream provider temporarily unavailable',
    504: 'Upstream provider timed out',
  };
  return { status, message: authentication ? 'Upstream authentication or access configuration failed' : messages[status] || 'Internal server error', ...(authentication ? { code: 'PROVIDER_AUTH_FAILED' } : {}) };
}
