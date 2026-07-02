"use strict";
// AUTHORED-BY Claude Opus 4.8
/**
 * The single https-or-loopback TRANSPORT POLICY for every credential-bearing URL the library
 * contacts — the OIDC issuer, and every endpoint discovered from its metadata (authorization /
 * token / registration). This is the ONE reviewed answer to "is this URL safe to send credentials
 * to", shared by both grant flows so neither can drift from the other.
 *
 * THE RULE (contrast with the @solid/reactive-authentication 0.1.3 bug): `https:` is always allowed;
 * `http:` is allowed ONLY for loopback hosts (`127.0.0.1`, `[::1]`, `localhost`) per RFC 8252 §8.3
 * and the OAuth security BCP; any other scheme is rejected. reactive-auth 0.1.3 rejected ALL `http:`
 * issuers outright, which broke local development against an in-memory CSS at `http://localhost` —
 * this module implements exactly the loopback carve-out that fixes that bug class without permitting
 * `http:` to a real (non-loopback) host.
 *
 * This is a LEAF module (no imports from the rest of the package), so both `session.ts` (the
 * client-credentials flow) and `authCode.ts` (the authorization-code flow) depend on it without a
 * cycle.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.isLoopbackHost = isLoopbackHost;
exports.assertIssuerTransport = assertIssuerTransport;
exports.assertEndpointTransport = assertEndpointTransport;
/** Loopback hosts for which `http:` is allowed (RFC 8252 §8.3). `localhost` included per the BCP. */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);
/** True iff `host` (a URL hostname, no port) is a loopback address. */
function isLoopbackHost(host) {
    return LOOPBACK_HOSTS.has(host.toLowerCase());
}
/**
 * Centralized transport policy: `https:` always allowed; `http:` allowed ONLY for loopback hosts;
 * any other scheme rejected. Backs BOTH the input-issuer guard ({@link assertIssuerTransport}) AND
 * the per-endpoint guard applied to discovered metadata ({@link assertEndpointTransport}), so a
 * discovered `token_endpoint` is held to the same bar as the issuer the caller typed.
 *
 * @param url   the URL to validate.
 * @param label a human label (e.g. `"issuer"`, `"token_endpoint"`) used in the thrown error.
 * @throws if the URL uses `http:` against a non-loopback host, or an unsupported scheme.
 */
function assertSecureTransport(url, label) {
    let u;
    try {
        u = new URL(url);
    }
    catch {
        throw new Error(`Invalid ${label} URL: ${url}`);
    }
    if (u.protocol === "https:")
        return;
    if (u.protocol === "http:") {
        if (isLoopbackHost(u.hostname))
            return;
        throw new Error(`Insecure ${label} ${url}: http is only permitted for loopback hosts ` +
            `(127.0.0.1, [::1], localhost). Use https for ${u.hostname}.`);
    }
    throw new Error(`Unsupported ${label} scheme ${u.protocol} in ${url} (expected https or http-loopback).`);
}
/**
 * Enforce the issuer transport policy: `https:` always allowed; `http:` allowed ONLY for loopback
 * hosts. This is the deliberate fix for the reactive-auth 0.1.3 "rejects all http issuers" bug —
 * it must NOT reject `http://localhost:3000/` while it MUST reject `http://idp.example.com/`.
 *
 * @throws if the issuer uses `http:` against a non-loopback host, or an unsupported scheme.
 */
function assertIssuerTransport(issuer) {
    assertSecureTransport(issuer, "issuer");
}
/**
 * Enforce the SAME https-or-loopback transport policy on a single DISCOVERED endpoint URL
 * (`authorization_endpoint`, `token_endpoint`, `registration_endpoint`, …). A malicious or
 * misconfigured discovery document could point an endpoint at an insecure non-loopback `http:` URL
 * (or a different origin) and siphon authorization codes, refresh tokens, or client secrets — so
 * every endpoint we will actually contact is validated, not just the input issuer.
 *
 * @throws if the endpoint uses `http:` against a non-loopback host, or an unsupported scheme.
 */
function assertEndpointTransport(endpoint, name) {
    assertSecureTransport(endpoint, name);
}
//# sourceMappingURL=transport.js.map