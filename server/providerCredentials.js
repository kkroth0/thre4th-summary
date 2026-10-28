const ABUSE_ENVS = ['ABUSE_CH_API_KEY','THREATFOX_API_KEY','URLHAUS_API_KEY','MALWAREBAZAAR_API_KEY'];
const ABUSE_PROVIDERS = ['abuse_ch','threatfox','urlhaus','malwarebazaar'];
export function personalProviderCredentials(provider, getKeys) {
  const own = getKeys(provider);
  return ABUSE_PROVIDERS.includes(provider) ? [...new Set([...own,...ABUSE_PROVIDERS.flatMap(getKeys)])] : own;
}
export function platformProviderCredentials(provider, env, getKeys) {
  const own = getKeys(env);
  if (!['abuse_ch','threatfox','urlhaus','malwarebazaar'].includes(provider)) return own;
  // Legacy dedicated values may have expired while a valid shared Auth-Key
  // exists. Keep those authentication fallbacks available, without discarding
  // the dedicated credential or resubmitting an upstream quota failure.
  return [...new Set([...own,...ABUSE_ENVS.flatMap(getKeys)])];
}
