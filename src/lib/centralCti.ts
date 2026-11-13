export const CENTRAL_CTI_PENDING = 'central-cti-pending';

export function pendingCentralCti() {
  const params = new URLSearchParams(sessionStorage.getItem(CENTRAL_CTI_PENDING) || '');
  if (Number(params.get('expires')) > Date.now()) return params.toString();
  sessionStorage.removeItem(CENTRAL_CTI_PENDING);
  return '';
}
