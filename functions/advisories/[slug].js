// Cloudflare Pages Function: /advisories/:slug
// Serve o SPA (index.html) mas injeta <title> + meta OG/Twitter do post, pra que
// links compartilhados (LinkedIn/X/WhatsApp/Slack) mostrem título e resumo certos
// em vez do genérico do site. Usuários normais recebem o mesmo HTML — o SPA
// hidrata e roteia como sempre. Qualquer falha cai no HTML base, nunca quebra.

const esc = (s) => String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#039;");

export async function onRequest(context) {
    const { request, env, params } = context;

    // HTML base servido pelo build do Pages.
    const assetRes = await env.ASSETS.fetch(new URL("/index.html", request.url));
    let html = await assetRes.text();

    try {
        const origin = (env.API_ORIGIN || "").replace(/\/+$/, "");
        const slug = Array.isArray(params.slug) ? params.slug[0] : params.slug;
        if (origin && slug) {
            const r = await fetch(`${origin}/api/posts/${encodeURIComponent(slug)}`, {
                headers: { accept: "application/json" },
            });
            if (r.ok) {
                const { post } = await r.json();
                if (post && post.published) {
                    const url = new URL(request.url);
                    const canonical = `${url.origin}/advisories/${post.slug}`;
                    const desc = esc(post.summary || post.title);
                    const injected = [
                        `<title>${esc(post.title)} · ThreatSumm4ry</title>`,
                        `<meta name="description" content="${desc}" />`,
                        `<meta property="og:title" content="${esc(post.title)}" />`,
                        `<meta property="og:description" content="${desc}" />`,
                        `<meta property="og:type" content="article" />`,
                        `<meta property="og:url" content="${esc(canonical)}" />`,
                        `<meta property="og:image" content="${url.origin}/threatsumm4ry-og-image-1200x630.png" />`,
                        `<meta name="twitter:card" content="summary_large_image" />`,
                        `<meta name="twitter:title" content="${esc(post.title)}" />`,
                        `<meta name="twitter:description" content="${desc}" />`,
                        `<link rel="canonical" href="${esc(canonical)}" />`,
                    ].join("\n  ");
                    // Remove os defaults (title/description/og:*) e injeta os do post.
                    html = html
                        .replace(/<title>.*?<\/title>/is, "")
                        .replace(/<meta\s+name="description"[^>]*>/is, "")
                        .replace(/<meta\s+property="og:(?:title|description|type)"[^>]*>/gis, "")
                        .replace("</head>", `  ${injected}\n</head>`);
                }
            }
        }
    } catch {
        // ignora — devolve o HTML base
    }

    return new Response(html, {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
    });
}
