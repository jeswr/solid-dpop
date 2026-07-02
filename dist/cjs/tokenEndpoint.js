"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultFetch = void 0;
exports.postToTokenEndpoint = postToTokenEndpoint;
// AUTHORED-BY Claude Opus 4.8
/**
 * The ONE reviewed implementation of a DPoP-bound POST to the OIDC token endpoint, shared by every
 * grant flow (client-credentials in `session.ts`; authorization-code + refresh in `authCode.ts`).
 * Consolidating it here means the RFC 9449 §8 `use_dpop_nonce` challenge handling — the security-
 * relevant retry that must be exactly-once and must echo the server nonce — is audited in a single
 * place instead of two copies that could silently diverge.
 *
 * This is a LEAF module w.r.t. runtime: it imports only `createDpopProof` from `dpop.js` (and the
 * `FetchLike` TYPE, erased at build). Callers own the deliberate per-flow request differences (the
 * form body, and which non-DPoP headers to send); this function adds ONLY the fresh per-attempt
 * `dpop` proof, so it never unifies those differences.
 */
const dpop_js_1 = require("./dpop.js");
/** The default transport: global fetch, narrowed to {@link FetchLike}. */
const defaultFetch = (input, init) => globalThis.fetch(input, init);
exports.defaultFetch = defaultFetch;
/**
 * POST a DPoP-bound request to the OIDC token `endpoint`, handling the RFC 9449 §8 `use_dpop_nonce`
 * challenge — a `400` carrying a `DPoP-Nonce` header — by retrying EXACTLY ONCE with that nonce
 * echoed into a fresh proof. Returns the parsed token response plus the latest server nonce; throws
 * on a non-2xx final response (message truncated to 300 chars).
 *
 * The caller supplies the full set of non-DPoP request headers in `baseHeaders` (`content-type`,
 * and — per grant — `accept` and/or a Basic `authorization` header). This function adds only the
 * `dpop` header, so the deliberate per-flow header differences are preserved by the callers.
 */
async function postToTokenEndpoint(endpoint, keyPair, body, baseHeaders, fetchImpl) {
    const attempt = async (nonce) => {
        const dpop = await (0, dpop_js_1.createDpopProof)({
            keyPair,
            htm: "POST",
            htu: endpoint,
            ...(nonce !== undefined ? { nonce } : {}),
        });
        return fetchImpl(endpoint, { method: "POST", headers: { ...baseHeaders, dpop }, body });
    };
    let res = await attempt();
    let nonce = res.headers.get("DPoP-Nonce") ?? undefined;
    if (res.status === 400 && nonce) {
        // RFC 9449 §8 nonce challenge — retry once with the server-supplied nonce.
        res = await attempt(nonce);
        nonce = res.headers.get("DPoP-Nonce") ?? nonce;
    }
    if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Token request failed (${res.status}): ${text.slice(0, 300)}`);
    }
    const token = (await res.json());
    return { token, ...(nonce ? { nonce } : {}) };
}
//# sourceMappingURL=tokenEndpoint.js.map