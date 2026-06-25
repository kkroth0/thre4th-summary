// Cloudflare Pages Function: reverse-proxy de /api/* para o backend na VPS,
// exposto via Cloudflare Tunnel. Mantém a MESMA ORIGEM (sem CORS) para que o
// front continue chamando "/api/..." sem nenhuma mudança.
//
// Requer a env var API_ORIGIN no projeto Pages, ex:
//   API_ORIGIN = https://origin.threatsumm4ry.app
export async function onRequest(context) {
  const { request, env } = context;
  const origin = (env.API_ORIGIN || "").replace(/\/+$/, "");
  if (!origin) {
    return new Response("API_ORIGIN not configured", { status: 500 });
  }

  const incoming = new URL(request.url);
  // incoming.pathname já inclui "/api/..."; preservamos path + querystring.
  const target = origin + incoming.pathname + incoming.search;

  const headers = new Headers(request.headers);
  headers.delete("host");
  // Repassa o IP real do cliente para o rate-limit/log do backend.
  const clientIp = request.headers.get("cf-connecting-ip");
  if (clientIp) headers.set("x-forwarded-for", clientIp);

  const method = request.method.toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";

  const init = {
    method,
    headers,
    redirect: "manual",
  };
  if (hasBody) {
    init.body = request.body;
    init.duplex = "half"; // necessário para stream de body em Workers runtime
  }

  const upstream = await fetch(target, init);
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: upstream.headers,
  });
}
