import { useState } from 'react';
export function ActorAvatar({ name, logo, large = false }: { name: string; logo?: string | null; large?: boolean }) {
  const [failed, setFailed] = useState(false);
  const permitted = logo && (/^\/images\/actors\/[a-zA-Z0-9-]+\.svg$/.test(logo) || /^https:\/\/images\.ransomware\.live\/groups\/favicons\/[a-zA-Z0-9_.%-]+\.png$/.test(logo));
  return <span className={`flex shrink-0 items-center justify-center overflow-hidden rounded-xl border bg-muted/30 font-semibold ${large ? 'h-20 w-20 text-xl' : 'h-12 w-12 text-xs'}`}>
    {permitted && !failed ? <img src={logo} alt={name} loading="lazy" referrerPolicy="no-referrer" className="h-full w-full object-contain p-1 dark:invert" onError={() => setFailed(true)} /> : <span aria-hidden>{name.split(/\s+/).map(part => part[0]).slice(0, 2).join('').toUpperCase()}</span>}
  </span>;
}
