// A read-only Solana RPC proxy, existing for one measured reason.
//
// THE BUG IT FIXES. The pay page asks "has this reference already settled?" before showing a
// payable card. Its pinned endpoint keeps a ROLLING retention window -- measured 2026-08-17, its
// firstAvailableBlock moved 439,097,325 -> 439,394,742 within hours -- so a settlement that has
// aged out returns exactly what an unpaid reference returns: an empty list. The page reads that as
// "not paid", leaves the card payable, and a customer reloading an older link can PAY TWICE.
//
// WHY A PROXY RATHER THAN A DIFFERENT PIN. Measured across eight keyless public endpoints, each
// sent a browser-shaped request carrying an Origin header:
//
//   solana-rpc.publicnode.com              200   <- the only one that answers a browser. Prunes.
//   api.mainnet-beta.solana.com            403       full history, refuses browsers
//   solana.drpc.org                        400
//   rpc.ankr.com/solana                    403
//   solana-mainnet.g.alchemy.com/v2/demo   429
//   solana.api.onfinality.io/public        429
//   endpoints.omniatech.io/.../public      521
//   api.blockeden.xyz/solana/<public>      402
//
// The ones that retain refuse browsers; the one that serves browsers prunes. There is no drop-in.
//
// THE KEY INSIGHT, and it is one HTTP header. mainnet-beta's 403 is triggered by the PRESENCE of
// an Origin header, not by identity, rate, or credential. One host, two calls, same minute:
//   no Origin  -> HTTP 200, 5 signatures      (what this Worker sends)
//   +Origin    -> HTTP 403                    (what a browser sends)
// CORRECTED: that inference was WRONG, and measuring it from inside the Worker is what showed it.
// mainnet-beta 403s a Cloudflare Worker too, by something other than the Origin header, so the
// no-Origin finding was true and the conclusion drawn from it was not. The deep endpoint is a
// KEYED provider reached with a Worker secret; the key never reaches the page, which preserves
// the property that mattered -- the pay page is static HTML anyone can view-source.
//
// KV MAKES THE UPSTREAM A CONVENIENCE RATHER THAN A DEPENDENCY. Every settlement this Worker
// resolves is recorded permanently, so once seen it survives ANY future pruning by ANY upstream.
// That is this project's standing preference for captured bytes over live links, applied to the
// pay path.
//
// TRUST: this proxy only ever READS. It cannot sign, cannot broadcast, and cannot move funds. A
// hostile answer can refuse a good link or withhold a confirmation; it cannot misdirect money,
// because the recipient, mint and amount are pinned in the page and shown again by the wallet.

// The deep endpoint is resolved from a SECRET at request time, never a constant. Measured from
// INSIDE this Worker rather than from a laptop -- that distinction is exactly what made the first
// pick wrong: ZERO of ten keyless endpoints can see a pruned settlement from Cloudflare egress.
// mainnet-beta and ankr 403 the Worker, drpc 400s, three rate-limit, two return 5xx, and
// publicnode answers but has already pruned it. Helius returned 401, the explicit "bring a key"
// signal, and with the key it reports firstAvailableBlock 0 and finds the settlement.
//
// The key lives ONLY here, server-side, set with `wrangler secret put HELIUS_API_KEY`. It never
// reaches the page. That is the whole reason a proxy was built instead of re-pinning the page: the
// pay page is static HTML anyone can view-source, so a key in it would be a published credential.
function deepEndpoint(env) {
  // No key means NO deep lookup, rather than a silent fallback to a host measured to 403 us. A
  // fallback that cannot work is worse than none: it looks like coverage and returns nothing.
  if (!env.HELIUS_API_KEY) return null;
  return "https://mainnet.helius-rpc.com/?api-key=" + env.HELIUS_API_KEY;
}
const UPSTREAM_FAST = "https://solana-rpc.publicnode.com";

// Deliberately a strict allowlist rather than a passthrough. An open JSON-RPC proxy on someone
// else's infrastructure is an abuse vector; this one answers exactly the question the pay page
// needs answered and nothing else.
const ALLOWED_METHODS = new Set(["getSignaturesForAddress", "getTransaction"]);

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,88}$/;

function cors(origin, allowed) {
  const h = {
    "content-type": "application/json",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
    "cache-control": "no-store",
  };
  // Prefix match rather than exact equality, because the harness serves the built page on an
  // EPHEMERAL PORT: the browser then sends `http://127.0.0.1:53219`, which no fixed string can
  // equal. An exact-match allowlist silently refused every local run while looking correct.
  if (origin && allowed.some((a) => origin === a || origin.startsWith(a + ":"))) {
    h["access-control-allow-origin"] = origin;
  }
  // Diagnostic, so a refused origin is legible instead of just absent.
  h["x-zc-origin-seen"] = origin || "none";
  h["x-zc-allowed-count"] = String(allowed.length);
  return h;
}

function err(id, code, message, headers) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message } }), {
    status: 200, // a JSON-RPC error is a successful HTTP exchange; the page reads `error`
    headers,
  });
}

async function upstream(url, body) {
  // No Origin header. That was ORIGINALLY the whole design and it did not survive measurement:
  // mainnet-beta 403s this Worker regardless. The header still matters for the fast endpoint,
  // and the deep one is reached with a key instead.
  //
  // The whole call is wrapped, not just the JSON parse. fetch REJECTS on a DNS failure, a TLS
  // error or a connection reset -- it does not merely return !ok -- so an unwrapped await here
  // takes down the request instead of falling through to the explicit "no upstream could answer".
  // Found by this Worker's own suite: a throwing fetch propagated out of the handler.
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) return { __status: r.status };
    return await r.json();
  } catch (e) {
    return { __status: `threw:${String(e).slice(0, 40)}` };
  }
}

export default {
  async fetch(request, env) {
    const allowed = (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
    const origin = request.headers.get("Origin");
    const headers = cors(origin, allowed);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (request.method !== "POST") return err(null, -32600, "POST only", headers);

    let body;
    try {
      body = await request.json();
    } catch {
      return err(null, -32700, "malformed JSON", headers);
    }

    const { id, method, params } = body || {};

    // Restored after a probe-block removal deleted it along with the block it sat beside. The
    // suite caught it on the next run, which is the whole reason case 1 exists: without this the
    // proxy is an open JSON-RPC relay on someone else's infrastructure.
    if (!ALLOWED_METHODS.has(method)) {
      return err(id, -32601, `method not proxied: ${String(method)}`, headers);
    }

    // Validate before the network, the same discipline the page and watch.rs already apply: a
    // reference lifted out of a hostile link never reaches an endpoint unless it is a pubkey.
    const first = Array.isArray(params) ? params[0] : null;
    if (typeof first !== "string" || !BASE58.test(first)) {
      return err(id, -32602, "first param must be a base58 pubkey or signature", headers);
    }

    const cacheKey = `${method}:${first}`;

    // 1. A recorded settlement is permanent and outlives any upstream's retention.
    if (env.SETTLEMENTS) {
      const hit = await env.SETTLEMENTS.get(cacheKey);
      if (hit) {
        return new Response(
          JSON.stringify({ jsonrpc: "2.0", id: id ?? null, result: JSON.parse(hit) }),
          { headers },
        );
      }
    }

    // 2. Fast endpoint first: it answers the common case and keeps load off the shared one.
    let out = await upstream(UPSTREAM_FAST, { jsonrpc: "2.0", id: 1, method, params });
    let result = out && !out.error && out.__status === undefined ? out.result : null;
    const fastResult = result;
    let deepTried = false;
    let deepResult = null;
    let deepStatus = "n/a";

    // 3. Escalate ONLY on an empty answer. An empty list is the ambiguous case -- pruned or never
    //    paid -- and the deep endpoint is the only thing that can tell them apart.
    const empty = result == null || (Array.isArray(result) && result.length === 0);
    // Skip the metered escalation if we asked recently and got nothing. The FAST lookup above still
    // ran, so a payment that lands during the quiet window is still seen on the next poll.
    const negRecent = empty && env.SETTLEMENTS ? await env.SETTLEMENTS.get(`neg:${cacheKey}`) : null;
    if (empty && !negRecent) {
      deepTried = true;
      const deepUrl = deepEndpoint(env);
      const deep = deepUrl
        ? await upstream(deepUrl, { jsonrpc: "2.0", id: 1, method, params })
        : null;
      deepResult = deep && !deep.error && deep.__status === undefined ? deep.result : null;
      if (deep && deep.__status !== undefined) deepStatus = String(deep.__status);
      if (deepResult != null) result = deepResult;
    }

    if (result == null) return err(id, -32603, "no upstream could answer", headers);

    // Diagnostics on the response itself rather than in a log, so a caller can see WHICH upstream
    // answered without needing `wrangler tail`. Cheap, and it makes a silent escalation failure
    // visible: an empty result with deep="null" means the deep endpoint refused this Worker.
    headers["x-zc-fast"] = String(Array.isArray(fastResult) ? fastResult.length : fastResult == null ? "null" : "obj");
    headers["x-zc-deep"] = deepTried
      ? String(Array.isArray(deepResult) ? deepResult.length : deepResult == null ? "null" : "obj")
      : "skipped";
    headers["x-zc-deep-status"] = deepStatus;
    headers["x-zc-allowed-0"] = JSON.stringify(allowed[0] || "");

    // 4. Record a settlement PERMANENTLY. Never record an empty answer at the same key: that would
    //    freeze "not paid" forever and recreate the double-payment bug with a longer memory.
    const settled = Array.isArray(result) ? result.length > 0 : result != null;
    if (env.SETTLEMENTS && settled) {
      await env.SETTLEMENTS.put(cacheKey, JSON.stringify(result));
    }

    // 4b. An empty answer gets a SHORT-LIVED negative marker under a DIFFERENT key, purely to stop
    //     the escalation hammering a metered upstream. Without it the cost is unbounded in the most
    //     ordinary case: the page polls an unpaid reference every 6s for 20 minutes, every poll
    //     finds the fast endpoint empty, and every one of those ~200 polls escalates. One open tab
    //     on an unpaid link would drive ~200 paid lookups.
    //
    //     TTL is deliberately shorter than the poll interval is long: 30s means a real payment is
    //     still noticed within one extra poll, so the page's whole reason for polling survives.
    //     The key is namespaced apart from the settlement key so a negative can NEVER be mistaken
    //     for a settlement, and the read path below only consults it to skip the escalation.
    if (env.SETTLEMENTS && !settled) {
      await env.SETTLEMENTS.put(`neg:${cacheKey}`, "1", { expirationTtl: 60 });
    }

    return new Response(JSON.stringify({ jsonrpc: "2.0", id: id ?? null, result }), { headers });
  },
};
