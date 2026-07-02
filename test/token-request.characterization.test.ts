// AUTHORED-BY Claude Opus 4.8
/**
 * CHARACTERIZATION of the exact TOKEN-ENDPOINT request shape for every grant flow.
 *
 * The three grant flows (client-credentials `acquireToken`, authorization-code `exchangeCode`,
 * refresh `refreshSession`) all POST a DPoP-bound request to the OIDC token endpoint and share the
 * RFC 9449 §8 `use_dpop_nonce` retry. This file pins the OBSERVABLE bytes each one puts on the wire
 * — the exact header key SET, each header value, the form body, and the §8 retry behaviour — BEFORE
 * that shared POST is consolidated into one reviewed implementation, so the consolidation is proven
 * to change SHAPE not BEHAVIOUR.
 *
 * The header differences between flows are DELIBERATE and pinned here so a refactor cannot silently
 * unify them: the client-credentials POST sends `authorization: Basic` + NO `accept`; the
 * authorization-code / refresh POST sends `accept: application/json` and `authorization` ONLY for a
 * confidential client. Never `--update` these — a diff is a behaviour change on the security path.
 */

import { decodeJwt, decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import {
  acquireToken,
  type ClientCredentials,
  type ClientRegistration,
  exchangeCode,
  type FetchLike,
  generateSessionKeyPair,
  type OidcProviderMetadata,
  refreshSession,
} from "../src/index.js";

const ISSUER = "http://localhost:3086/";
const TOKEN_ENDPOINT = "http://localhost:3086/token";
const DISCOVERY = "http://localhost:3086/.well-known/openid-configuration";

const META: OidcProviderMetadata = {
  issuer: ISSUER,
  authorization_endpoint: "http://localhost:3086/auth",
  token_endpoint: TOKEN_ENDPOINT,
  registration_endpoint: "http://localhost:3086/reg",
};

type Call = { url: string; init?: Parameters<FetchLike>[1] };

function tokenResponse(over: Record<string, unknown> = {}): Response {
  return new Response(
    JSON.stringify({ access_token: "at-xyz", token_type: "DPoP", expires_in: 300, ...over }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

describe("CHARACTERIZATION: client-credentials token request (acquireToken)", () => {
  it("POSTs the exact header set + body — Basic auth, form content-type, DPoP, NO accept", async () => {
    const calls: Call[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({ url, init });
      if (url === DISCOVERY) {
        return new Response(JSON.stringify({ token_endpoint: TOKEN_ENDPOINT }), {
          headers: { "content-type": "application/json" },
        });
      }
      return tokenResponse();
    };
    const creds: ClientCredentials = { issuer: ISSUER, id: "cid", secret: "csec" };
    const kp = await generateSessionKeyPair();
    await acquireToken(creds, kp, fetchImpl);

    // Discovery is a bare GET to the well-known URL.
    expect(calls[0]?.url).toBe(DISCOVERY);
    expect(calls[0]?.init).toBeUndefined();

    const tokenCall = calls.find((c) => c.url === TOKEN_ENDPOINT);
    expect(tokenCall?.init?.method).toBe("POST");
    const headers = tokenCall?.init?.headers ?? {};
    // EXACT header key set — pins that `accept` is NOT sent on this flow.
    expect(Object.keys(headers).sort()).toEqual(["authorization", "content-type", "dpop"]);
    expect(headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(headers["authorization"]).toBe(`Basic ${Buffer.from("cid:csec").toString("base64")}`);
    // Form body is exactly the client-credentials grant with the webid scope.
    expect(tokenCall?.init?.body).toBe("grant_type=client_credentials&scope=webid");
    // The DPoP proof binds POST to the token endpoint.
    const proof = headers["dpop"] as string;
    expect(decodeProtectedHeader(proof).typ).toBe("dpop+jwt");
    const payload = decodeJwt(proof);
    expect(payload["htm"]).toBe("POST");
    expect(payload["htu"]).toBe(TOKEN_ENDPOINT);
    expect(payload["ath"]).toBeUndefined(); // no access token at the token endpoint
  });

  it("credentials are URL-encoded into the Basic header (special chars)", async () => {
    let auth: string | undefined;
    const fetchImpl: FetchLike = async (url, init) => {
      if (url === DISCOVERY) {
        return new Response(JSON.stringify({ token_endpoint: TOKEN_ENDPOINT }), {
          headers: { "content-type": "application/json" },
        });
      }
      auth = init?.headers?.["authorization"];
      return tokenResponse();
    };
    const creds: ClientCredentials = { issuer: ISSUER, id: "a:b", secret: "p@ss word" };
    await acquireToken(creds, await generateSessionKeyPair(), fetchImpl);
    const expected = `Basic ${Buffer.from(
      `${encodeURIComponent("a:b")}:${encodeURIComponent("p@ss word")}`,
    ).toString("base64")}`;
    expect(auth).toBe(expected);
  });

  it("§8: retries once with the nonce; retried proof carries it; returns the nonce", async () => {
    let hits = 0;
    const proofs: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      if (url === DISCOVERY) {
        return new Response(JSON.stringify({ token_endpoint: TOKEN_ENDPOINT }), {
          headers: { "content-type": "application/json" },
        });
      }
      hits += 1;
      proofs.push(init?.headers?.["dpop"] as string);
      if (hits === 1) return new Response("{}", { status: 400, headers: { "DPoP-Nonce": "N1" } });
      return tokenResponse();
    };
    const creds: ClientCredentials = { issuer: ISSUER, id: "cid", secret: "csec" };
    const { nonce } = await acquireToken(creds, await generateSessionKeyPair(), fetchImpl);
    expect(hits).toBe(2);
    expect(nonce).toBe("N1");
    expect(decodeJwt(proofs[0] as string)["nonce"]).toBeUndefined(); // first proof: no nonce
    expect(decodeJwt(proofs[1] as string)["nonce"]).toBe("N1"); // retry: echoes the nonce
  });
});

describe("CHARACTERIZATION: authorization-code token request (exchangeCode)", () => {
  it("public client: exact header set (accept, NO authorization) + form body", async () => {
    let tokenCall: Call | undefined;
    const fetchImpl: FetchLike = async (url, init) => {
      tokenCall = { url, init };
      return tokenResponse({ refresh_token: "rt-1" });
    };
    const client: ClientRegistration = {
      client_id: "pub-1",
      redirect_uris: ["http://127.0.0.1/cb"],
    };
    await exchangeCode({
      meta: META,
      client,
      redirectUri: "http://127.0.0.1/cb",
      code: "the-code",
      codeVerifier: "the-verifier",
      fetchImpl,
    });
    expect(tokenCall?.url).toBe(TOKEN_ENDPOINT);
    const headers = tokenCall?.init?.headers ?? {};
    // Public client: accept present, authorization ABSENT (PKCE-only auth).
    expect(Object.keys(headers).sort()).toEqual(["accept", "content-type", "dpop"]);
    expect(headers["accept"]).toBe("application/json");
    expect(headers["content-type"]).toBe("application/x-www-form-urlencoded");
    const body = new URLSearchParams(tokenCall?.init?.body as string);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("the-code");
    expect(body.get("redirect_uri")).toBe("http://127.0.0.1/cb");
    expect(body.get("code_verifier")).toBe("the-verifier");
    expect(body.get("client_id")).toBe("pub-1");
  });

  it("confidential client: adds Basic authorization alongside accept", async () => {
    let headers: Record<string, string> = {};
    const fetchImpl: FetchLike = async (_url, init) => {
      headers = init?.headers ?? {};
      return tokenResponse();
    };
    const client: ClientRegistration = {
      client_id: "conf-1",
      client_secret: "shh",
      redirect_uris: ["http://127.0.0.1/cb"],
    };
    await exchangeCode({
      meta: META,
      client,
      redirectUri: "http://127.0.0.1/cb",
      code: "c",
      codeVerifier: "v",
      fetchImpl,
    });
    expect(Object.keys(headers).sort()).toEqual([
      "accept",
      "authorization",
      "content-type",
      "dpop",
    ]);
    expect(headers["authorization"]).toBe(`Basic ${Buffer.from("conf-1:shh").toString("base64")}`);
  });
});

describe("CHARACTERIZATION: refresh token request (refreshSession)", () => {
  it("POSTs grant_type=refresh_token with the refresh token + client_id", async () => {
    const seed: FetchLike = async () => tokenResponse({ refresh_token: "rt-1" });
    const session = await exchangeCode({
      meta: META,
      client: { client_id: "pub-1", redirect_uris: ["http://127.0.0.1/cb"] },
      redirectUri: "http://127.0.0.1/cb",
      code: "c",
      codeVerifier: "v",
      fetchImpl: seed,
    });
    let body: URLSearchParams | undefined;
    const refreshFetch: FetchLike = async (_url, init) => {
      body = new URLSearchParams(init?.body as string);
      return tokenResponse({ access_token: "at-2", refresh_token: "rt-2" });
    };
    await refreshSession(session, refreshFetch);
    expect(body?.get("grant_type")).toBe("refresh_token");
    expect(body?.get("refresh_token")).toBe("rt-1");
    expect(body?.get("client_id")).toBe("pub-1");
  });
});
