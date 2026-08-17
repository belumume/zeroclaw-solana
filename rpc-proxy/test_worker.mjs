// Controls for the RPC proxy, run against the REAL handler and, wherever reality allows, the REAL
// endpoints.
//
// WHY REAL RATHER THAN SIMULATED. The condition this Worker exists for is live right now: the
// pinned fast endpoint has pruned reference 9TNKoCv... and returns an empty list, while the deep
// endpoint still returns its five finalized signatures. Simulating that would only prove the code
// matches my belief about the network. Hitting it proves the thing.
//
// The ONLY simulated case is "both upstreams down", because a real outage cannot be summoned on
// demand. It is marked SIMULATED in its own name so nobody mistakes its scope.
//
// Network cases self-skip as NOT RUN rather than failing when the network is unavailable -- a
// missing network is not evidence about this code. The offline cases carry a floor so a total
// skip cannot read as a pass.
//
// Run: node rpc-proxy/test_worker.mjs

import worker from "./src/index.js";

const REF_SETTLED = "9TNKoCvVow1ktRgMMapJ9d9GWhgTYCA9i3r3MZ71FUT2"; // settled, pruned on the fast endpoint
const REF_UNPAID = "5Zzguz4NsSRFxGkHfM4KmJTNVPMJ2P3jFa2y8bTHY4kW"; // valid pubkey, zero history
const ORIGIN = "https://belumume.github.io";
const MIN_OFFLINE = 10; // measured; raise when an offline case is added or this under-asserts

let pass = 0,
  fail = 0,
  notrun = 0,
  offlineScored = 0;

const check = (name, cond, detail = "") => {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.log(`  FAIL  ${name}  ${detail}`);
  }
};

const realFetch = globalThis.fetch;

function kv() {
  const m = new Map();
  return { store: m, get: async (k) => m.get(k) ?? null, put: async (k, v) => void m.set(k, v) };
}
// The deep endpoint is secret-backed, so the suite must supply the same env the Worker gets or the
// live cases test a Worker with no deep lookup at all and fail for the wrong reason. Read from the
// gitignored secrets file the rest of this project uses; NEVER hardcoded, never printed.
import { readFileSync } from "node:fs";
const HELIUS_API_KEY = (() => {
  // ENV FIRST, so this works on a CI runner where the gitignored secrets file does not exist.
  // The file is the local convenience; the variable is what the workflow supplies. Without this
  // ordering the CI wiring would look correct and the live cases would silently self-skip forever.
  if (process.env.HELIUS_API_KEY) return process.env.HELIUS_API_KEY;
  try {
    for (const line of readFileSync(new URL("../.secrets/api-keys.env", import.meta.url), "utf8").split("\n")) {
      const i = line.indexOf("=");
      if (i > 0 && line.slice(0, i).trim() === "HELIUS_API_KEY") return line.slice(i + 1).trim().replace(/^["']|["']$/g, "");
    }
  } catch {
    /* absent is fine: the live cases self-skip below rather than failing */
  }
  return "";
})();

const env = () => ({ ALLOWED_ORIGINS: `${ORIGIN},http://127.0.0.1`, SETTLEMENTS: kv(), HELIUS_API_KEY });

const ask = (e, body, origin = ORIGIN) =>
  worker
    .fetch(
      new Request("https://proxy.test/", {
        method: "POST",
        headers: { "content-type": "application/json", ...(origin ? { Origin: origin } : {}) },
        body: JSON.stringify(body),
      }),
      e,
    )
    .then(async (r) => ({ headers: r.headers, json: await r.json() }));

const sigsReq = (ref) => ({ jsonrpc: "2.0", id: 1, method: "getSignaturesForAddress", params: [ref] });

console.log("rpc-proxy controls\n");

// ---------- OFFLINE: no network needed, these are the floor ----------------------------------
{
  globalThis.fetch = async () => {
    throw new Error("offline cases must not touch the network");
  };

  const r1 = await ask(env(), { jsonrpc: "2.0", id: 1, method: "sendTransaction", params: [REF_SETTLED] });
  check("1  a non-allowlisted method is refused before any network call", r1.json.error?.code === -32601);
  offlineScored++;

  const r2 = await ask(env(), { jsonrpc: "2.0", id: 1, method: "getSignaturesForAddress", params: ["../../etc/passwd"] });
  check("2  a non-base58 param is refused before any network call", r2.json.error?.code === -32602);
  offlineScored++;

  const r3 = await ask(env(), { jsonrpc: "2.0", id: 1, method: "getSignaturesForAddress", params: [] });
  check("3  a missing param is refused", r3.json.error?.code === -32602);
  offlineScored++;

  // A recorded settlement answers with the network hard-broken, which is the durability claim.
  const e4 = env();
  await e4.SETTLEMENTS.put(`getSignaturesForAddress:${REF_SETTLED}`, JSON.stringify([{ signature: "abc", err: null }]));
  const r4 = await ask(e4, sigsReq(REF_SETTLED));
  check("4  a recorded settlement is served with the network unavailable", r4.json.result?.length === 1);
  offlineScored++;

  // Pre-seeded so these resolve from the cache and stay genuinely offline. Without the seed they
  // fall through to the network, which is what the throwing stub above caught on the first run.
  const seed = async () => {
    const e = env();
    await e.SETTLEMENTS.put(`getSignaturesForAddress:${REF_SETTLED}`, JSON.stringify([{ signature: "abc", err: null }]));
    return e;
  };
  const r5 = await ask(await seed(), sigsReq(REF_SETTLED), ORIGIN);
  check("5  an allowed origin gets the CORS header", r5.headers.get("access-control-allow-origin") === ORIGIN);
  offlineScored++;
  const r6 = await ask(await seed(), sigsReq(REF_SETTLED), "https://evil.test");
  check("6  CONTROL: an unlisted origin gets NO CORS header", r6.headers.get("access-control-allow-origin") === null);
  offlineScored++;

  // The handler must SURVIVE a fetch that REJECTS, not just one that returns !ok. fetch rejects on
  // DNS failure, TLS error and connection reset. Caught by the first run of this suite, where an
  // unwrapped await propagated straight out of the handler.
  globalThis.fetch = async () => {
    throw new Error("simulated connection reset");
  };
  const r6b = await ask(env(), sigsReq(REF_SETTLED));
  check("6b a REJECTING fetch degrades to an error response rather than crashing", r6b.json.error?.code === -32603);
  offlineScored++;

  // 6c/6d. THE NEGATIVE MARKER MUST NOT BE REFRESHED ON A SKIPPED ESCALATION. This is the bug the
  // last commit fixed, and review pointed out that nothing would have caught it or a regression
  // back to it -- on a branch whose whole thesis is "make the controls actually run". The KV mock
  // does not model expirationTtl, so expiry itself is not simulated; what IS asserted is the thing
  // that went wrong: whether `neg:` gets WRITTEN AGAIN on a call that skipped the escalation.
  // Unguarded, every 6s poll rewrote it and the 60s TTL never elapsed, so the deep lookup fired
  // once per session instead of once a minute.
  {
    let deepCalls = 0;
    globalThis.fetch = async (url) => {
      if (!String(url).includes("publicnode")) deepCalls++;
      return { ok: true, json: async () => ({ jsonrpc: "2.0", id: 1, result: [] }) };
    };
    const e = { ...env(), HELIUS_API_KEY: "test-key-not-a-real-credential" };
    const negKey = `neg:getSignaturesForAddress:${REF_UNPAID}`;

    await ask(e, sigsReq(REF_UNPAID)); // escalates, writes the marker
    const afterFirst = e.SETTLEMENTS.store.get(negKey);
    const deepAfterFirst = deepCalls;
    e.SETTLEMENTS.store.set(negKey, "SENTINEL"); // a rewrite would clobber this
    await ask(e, sigsReq(REF_UNPAID)); // marker present -> must SKIP and not rewrite

    check("6c the escalation is skipped while the negative marker is present", deepCalls === deepAfterFirst,
      `deep calls went ${deepAfterFirst} -> ${deepCalls}`);
    check("6d and the marker is NOT rewritten on that skip, so its TTL can actually elapse",
      e.SETTLEMENTS.store.get(negKey) === "SENTINEL",
      `marker is now ${JSON.stringify(e.SETTLEMENTS.store.get(negKey))}; a rewrite means the TTL refreshes forever`);
    offlineScored += 2;
    void afterFirst;
  }

  // SIMULATED, and named so: a real outage cannot be summoned. Everything else here is real.
  globalThis.fetch = async () => ({ ok: false, json: async () => ({}) });
  const r7 = await ask(env(), sigsReq(REF_SETTLED));
  check("7  SIMULATED both upstreams down -> explicit error, never a fabricated empty", r7.json.error?.code === -32603);
  offlineScored++;

  globalThis.fetch = realFetch;
}

// ---------- LIVE: the condition this Worker exists for is real right now ----------------------
let reachable = true;
try {
  const probe = await realFetch("https://solana-rpc.publicnode.com", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getHealth", params: [] }),
  });
  reachable = probe.ok;
} catch {
  reachable = false;
}

if (!reachable || !HELIUS_API_KEY) {
  notrun += 3;
  const why = !reachable ? "network unavailable" : "no HELIUS_API_KEY in .secrets/api-keys.env";
  console.log(`\n  NOT RUN  ${why}; the live cases need it (offline floor still enforced)`);
} else {
  console.log("");
  // THE POINT, against real endpoints: the fast one has pruned this settlement, the deep one has
  // not, and the Worker must surface it. If the fast endpoint ever un-prunes it this still passes,
  // which is correct -- the assertion is "the settlement is found", not "the escalation happened".
  const e = env();
  const r = await ask(e, sigsReq(REF_SETTLED));
  const found = Array.isArray(r.json.result) && r.json.result.length > 0;
  check("8  LIVE: the settlement is found even though the fast endpoint pruned it", found, JSON.stringify(r.json).slice(0, 160));
  check("9  LIVE: and it was recorded, so it now survives any future pruning", e.SETTLEMENTS.store.size === 1);

  // CONTROL against the same real network: a genuinely unpaid reference must stay unpaid, or the
  // page would refuse a payable link -- the opposite failure, equally bad.
  const e2 = env();
  const r2 = await ask(e2, sigsReq(REF_UNPAID));
  const empty = Array.isArray(r2.json.result) && r2.json.result.length === 0;
  // Asserts the INVARIANT, not the store's size. The size was a proxy for "not cached" and went
  // red when a short-lived NEGATIVE marker was added to stop an unpaid reference escalating to a
  // metered upstream on all ~200 polls of a 20-minute window. A namespaced `neg:` key with a TTL
  // is not a settlement; what must never happen is an empty answer being recorded UNDER THE
  // SETTLEMENT KEY, because that would serve "not paid" forever and rebuild the double-payment bug.
  const settlementKey = `getSignaturesForAddress:${REF_UNPAID}`;
  const noSettlementRecorded = !e2.SETTLEMENTS.store.has(settlementKey);
  // And it must STILL read empty on a second call rather than serving anything from the marker.
  const r2b = await ask(e2, sigsReq(REF_UNPAID));
  const stillEmpty = Array.isArray(r2b.json.result) && r2b.json.result.length === 0;
  check(
    "10 LIVE CONTROL: an unpaid reference stays empty and is never recorded as settled",
    empty && noSettlementRecorded && stillEmpty,
    `empty=${empty} noSettlementKey=${noSettlementRecorded} stillEmptyOnRepeat=${stillEmpty} keys=${[...e2.SETTLEMENTS.store.keys()]}`,
  );
}

console.log(`\n${pass} passed, ${fail} failed, ${notrun} not run`);
if (offlineScored < MIN_OFFLINE) {
  console.log(`\nFAIL  only ${offlineScored} offline case(s) scored, below the floor of ${MIN_OFFLINE}.`);
  process.exit(1);
}
process.exit(fail ? 1 : 0);
