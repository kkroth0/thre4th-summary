// Himetrica · client-side analytics wrappers.
//
// The tracker itself is loaded by the <script defer src="cdn.himetrica.com/…">
// in index.html; it populates `window.himetrica` once it runs. These wrappers
// exist so the rest of the app calls analytics through a typed, guarded API:
//   - safe to call before the deferred script has loaded (no-op instead of throw)
//   - analytics failures never break the app (try/catch)
//
// Everything here runs in the browser only — there is no server-side analytics.

export interface HimetricaUser {
    name?: string;
    email?: string;
    metadata?: Record<string, string | number | boolean | null | undefined>;
}

interface Himetrica {
    track: (event: string, props?: Record<string, unknown>) => void;
    identify: (user: HimetricaUser) => void;
}

declare global {
    interface Window {
        himetrica?: Himetrica;
    }
}

/** Track a custom event. No-ops if the tracker hasn't loaded yet. */
export function track(event: string, props?: Record<string, unknown>): void {
    try {
        window.himetrica?.track(event, props);
    } catch {
        /* analytics must never break the app */
    }
}

/** Identify the current user after login. No-ops if the tracker hasn't loaded. */
export function identify(user: HimetricaUser): void {
    try {
        window.himetrica?.identify(user);
    } catch {
        /* analytics must never break the app */
    }
}
