(() => {
    const path = window.location.pathname;
    if (path === '/central-cti') return;

    if (path === '/profile' || path === '/login') {
        try {
            const transfer = new URLSearchParams(sessionStorage.getItem('central-cti-pending') || '');
            if (Number(transfer.get('expires')) > Date.now()) return;
        } catch {
            // Analytics can still load when session storage is unavailable.
        }
    }

    const tracker = document.createElement('script');
    tracker.src = 'https://cdn.himetrica.com/tracker.js';
    tracker.dataset.apiKey = document.currentScript.dataset.apiKey;
    document.head.append(tracker);
})();
