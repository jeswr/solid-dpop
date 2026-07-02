"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.discoveryUrl = discoveryUrl;
exports.generateSessionKeyPair = generateSessionKeyPair;
exports.acquireToken = acquireToken;
exports.createSession = createSession;
exports.authedFetch = authedFetch;
exports.rdfFetchFor = rdfFetchFor;
/**
 * Server-side Solid-OIDC session: the consumer custodies one DPoP keypair + access token
 * per connection and uses them to make sender-constrained (RFC 9449) requests to a pod.
 *
 * Token acquisition here uses the **client-credentials** grant (CSS `.account` API):
 * the connection is provisioned with a CSS client-credentials token `{id, secret}` that
 * is exchanged at the OIDC `token_endpoint` for a DPoP-bound access token. This is the
 * grant a self-hosted / service-account consumer uses. A user-delegated consumer would
 * instead hold a refresh token from an authorization-code flow; the resource-request half
 * (`authedFetch`) is identical, only `acquireToken` differs.
 */
const dpop_js_1 = require("./dpop.js");
const tokenEndpoint_js_1 = require("./tokenEndpoint.js");
/**
 * Build the OIDC Discovery URL for an issuer. Per OpenID Connect Discovery 1.0 §4, the well-known
 * suffix is APPENDED to the issuer (including any path), so `https://host/realm` →
 * `https://host/realm/.well-known/openid-configuration`. The naive `new URL(".well-known/...",
 * issuer)` resolves relative to the issuer's *parent* and drops the last path segment (`/realm`),
 * breaking non-root issuers like Keycloak realms.
 */
function discoveryUrl(issuer) {
    const u = new URL(issuer);
    u.pathname = `${u.pathname.replace(/\/+$/, "")}/.well-known/openid-configuration`;
    return u.toString();
}
async function discoverTokenEndpoint(issuer, fetchImpl) {
    const url = discoveryUrl(issuer);
    const res = await fetchImpl(url);
    if (!res.ok) {
        throw new Error(`OIDC discovery failed (${res.status}) at ${url}`);
    }
    const cfg = (await res.json());
    if (!cfg.token_endpoint) {
        throw new Error(`No token_endpoint in OIDC config at ${url}`);
    }
    return cfg.token_endpoint;
}
/** Generate a fresh DPoP keypair for a new session. node:crypto/jose only — no hand-rolled keygen. */
async function generateSessionKeyPair() {
    return (0, dpop_js_1.generateDpopKeyPair)();
}
/**
 * Exchange client-credentials for a DPoP-bound access token. Handles the RFC 9449 §8
 * `use_dpop_nonce` challenge: if the AS rejects the first attempt demanding a nonce, we
 * retry once with the supplied `DPoP-Nonce`.
 */
async function acquireToken(creds, keyPair, fetchImpl = tokenEndpoint_js_1.defaultFetch) {
    const tokenEndpoint = await discoverTokenEndpoint(creds.issuer, fetchImpl);
    const authHeader = "Basic " +
        Buffer.from(`${encodeURIComponent(creds.id)}:${encodeURIComponent(creds.secret)}`).toString("base64");
    const body = new URLSearchParams({
        grant_type: "client_credentials",
        scope: "webid",
    }).toString();
    // Client-credentials always authenticates with Basic; it does NOT send an `accept` header.
    const { token, nonce } = await (0, tokenEndpoint_js_1.postToTokenEndpoint)(tokenEndpoint, keyPair, body, { authorization: authHeader, "content-type": "application/x-www-form-urlencoded" }, fetchImpl);
    const expiresAt = Date.now() + (token.expires_in ?? 300) * 1000;
    return { accessToken: token.access_token, expiresAt, ...(nonce ? { nonce } : {}) };
}
/** Create a fully-initialised server-side session (keypair + first token). */
async function createSession(creds, fetchImpl = tokenEndpoint_js_1.defaultFetch) {
    const keyPair = await generateSessionKeyPair();
    const { accessToken, expiresAt, nonce } = await acquireToken(creds, keyPair, fetchImpl);
    return { keyPair, accessToken, expiresAt, ...(nonce ? { nonce } : {}) };
}
/**
 * Make a DPoP-bound request to a pod resource. Sends `Authorization: DPoP <token>` plus a
 * fresh per-request DPoP proof carrying the `ath` binding. Handles the §8 nonce challenge
 * (401 + DPoP-Nonce) with a single retry, persisting the nonce on the session.
 *
 * `creds` is the client-credentials token used to silently re-mint an expired access token. It is
 * OPTIONAL: a user-delegated (authorization-code) session has no client-credentials and instead
 * refreshes via `refreshSession` from `authCode.ts`, so it passes `undefined` here — in that case
 * an expired token is left as-is for the caller (or its own refresh loop) to handle.
 */
async function authedFetch(session, creds, method, url, init = {}, fetchImpl = tokenEndpoint_js_1.defaultFetch) {
    if (creds && Date.now() >= session.expiresAt) {
        const refreshed = await acquireToken(creds, session.keyPair, fetchImpl);
        session.accessToken = refreshed.accessToken;
        session.expiresAt = refreshed.expiresAt;
        if (refreshed.nonce)
            session.nonce = refreshed.nonce;
    }
    const doRequest = async (nonce) => {
        const dpop = await (0, dpop_js_1.createDpopProof)({
            keyPair: session.keyPair,
            htm: method,
            htu: url,
            accessToken: session.accessToken,
            ...(nonce !== undefined ? { nonce } : {}),
        });
        const headers = {
            ...(init.headers ?? {}),
            authorization: `DPoP ${session.accessToken}`,
            dpop,
        };
        return fetchImpl(url, {
            method,
            headers,
            ...(init.body !== undefined ? { body: init.body } : {}),
        });
    };
    let res = await doRequest(session.nonce);
    const challenge = res.headers.get("DPoP-Nonce");
    if (res.status === 401 && challenge && challenge !== session.nonce) {
        session.nonce = challenge;
        res = await doRequest(session.nonce);
        const next = res.headers.get("DPoP-Nonce");
        if (next)
            session.nonce = next;
    }
    else {
        const next = res.headers.get("DPoP-Nonce");
        if (next)
            session.nonce = next;
    }
    return res;
}
/**
 * Build an RDF-capable fetch (the signature `@jeswr/fetch-rdf` expects) bound to this session.
 * Adapts the standard DOM `fetch` signature down onto `authedFetch`, so RDF helpers that take a
 * `fetch` option can transparently issue DPoP-bound requests.
 */
function rdfFetchFor(session, creds, fetchImpl = tokenEndpoint_js_1.defaultFetch) {
    return (async (input, init) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        const method = init?.method ?? "GET";
        const headers = {};
        if (init?.headers) {
            new Headers(init.headers).forEach((v, k) => {
                headers[k] = v;
            });
        }
        const body = init?.body;
        return authedFetch(session, creds, method, url, { headers, ...(body !== undefined ? { body } : {}) }, fetchImpl);
    });
}
//# sourceMappingURL=session.js.map