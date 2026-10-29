// Use public-plan ceilings unless the operator configures another allowance.
// Provider cooldowns remain authoritative and are never cleared here.
export function providerCredentialLimits(provider, prefix, env = process.env) {
  const defaults = provider === 'virustotal' ? { perMinute: 4, perDay: 500 } : { perMinute: 0, perDay: 0 };
  const read = (suffix, fallback) => {
    const value = env[`${prefix}_${suffix}`];
    if (value == null || String(value).trim() === '') return fallback;
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
  };
  return {
    perMinute: read('REQUESTS_PER_MINUTE', defaults.perMinute),
    perDay: read('REQUESTS_PER_DAY', defaults.perDay),
    ...(provider === 'otx' ? { maxConcurrent: 2 } : {}),
  };
}
