/**
 * @jeswr/solid-dpop — the canonical Solid-OIDC client-credentials session + RFC 9449 DPoP proof
 * primitives, plus the user-delegated authorization-code + PKCE + DPoP flow. `jose`-only crypto;
 * dual ESM + CJS build committed to `dist/` so consumers `github:`-install it with no build step.
 *
 * PUBLIC package (`@jeswr/solid-dpop`), consumed by `@jeswr/solid-openid-client`, `@jeswr/auth-solid`
 * and the Solid app forks' DPoP paths. This barrel is the `.` entry point; the test-only headless
 * OIDC driver ships from the separate `@jeswr/solid-dpop/testing` subpath (never re-exported here).
 */
/**
 * Solid-OIDC authorization-code + PKCE + DPoP — the *user-delegated* login. Produces an
 * `AuthCodeSession` (a `SolidSessionState` + refresh token) usable with the same `authedFetch` /
 * `rdfFetchFor` surface as the client-credentials session.
 */
export { assertEndpointTransport, assertIssuerTransport, buildAuthorizationUrl, cliLogin, DEFAULT_SCOPE, discoverProvider, exchangeCode, generatePkce, isLoopbackHost, pkceChallengeS256, refreshSession, registerClient, startLoopbackListener, staticClient, } from "./authCode.js";
export { accessTokenHash, canonicalHtu, createDpopProof, DPOP_ALG, exportDpopKeyPairJwk, generateDpopKeyPair, importDpopKeyPairJwk, toDpopKeyPair, } from "./dpop.js";
export { acquireToken, authedFetch, createSession, discoveryUrl, generateSessionKeyPair, rdfFetchFor, } from "./session.js";
/**
 * Persist a user-delegated session to disk (`0600`) so a CLI logs in once and later runs reuse it
 * via the refresh grant. The DPoP private key is stored because CSS binds the refresh token to the
 * original `jkt` — regenerating the keypair fails refresh (verified live). See sessionStore.ts.
 */
export { deserializeSession, loadSession, saveSession, serializeSession, } from "./sessionStore.js";
//# sourceMappingURL=index.js.map