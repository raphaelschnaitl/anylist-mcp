/**
 * Single sign-on (OIDC) tests: the real routers against a fake identity provider that
 * issues signed ID tokens. No network beyond 127.0.0.1, no AnyList credentials.
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { createHash, randomBytes } from "crypto";
import { fileURLToPath } from "url";
import express from "express";
import session from "express-session";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

const CLIENT_ID = "anylist-client";
const CLIENT_SECRET = "anylist-secret";

// ── Fake identity provider ───────────────────────────────────────────────────

const { publicKey, privateKey } = await generateKeyPair("RS256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
const pendingCodes = new Map(); // code → { nonce, challenge, redirectUri, identity }
let nextIdentity; // claims the next sign-in returns

const idp = express();
idp.use(express.urlencoded({ extended: false }));
let issuer;
idp.get("/.well-known/openid-configuration", (_req, res) => res.json({
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  jwks_uri: `${issuer}/jwks`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
}));
idp.get("/jwks", (_req, res) => res.json({ keys: [jwk] }));
idp.get("/authorize", (req, res) => {
  const { redirect_uri, state, nonce, code_challenge, client_id } = req.query;
  assert.equal(client_id, CLIENT_ID);
  const code = randomBytes(8).toString("hex");
  pendingCodes.set(code, { nonce, challenge: code_challenge, redirectUri: redirect_uri, identity: nextIdentity });
  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);
  res.redirect(url.href);
});
idp.post("/token", async (req, res) => {
  const basic = (req.headers.authorization || "").replace(/^Basic /, "");
  const [id, secret] = basic
    ? Buffer.from(basic, "base64").toString().split(":").map(decodeURIComponent)
    : [req.body.client_id, req.body.client_secret];
  if (id !== CLIENT_ID || secret !== CLIENT_SECRET) return res.status(401).json({ error: "invalid_client" });
  const pending = pendingCodes.get(req.body.code);
  pendingCodes.delete(req.body.code);
  if (!pending || pending.redirectUri !== req.body.redirect_uri) return res.status(400).json({ error: "invalid_grant" });
  const challenge = createHash("sha256").update(req.body.code_verifier || "").digest("base64url");
  if (challenge !== pending.challenge) return res.status(400).json({ error: "invalid_grant" });
  const idToken = await new SignJWT({ ...pending.identity, nonce: pending.nonce })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(issuer).setAudience(CLIENT_ID).setIssuedAt().setExpirationTime("5m")
    .sign(privateKey);
  res.json({ access_token: "at", token_type: "Bearer", expires_in: 300, id_token: idToken });
});

let idpServer;
await new Promise(resolve => { idpServer = idp.listen(0, "127.0.0.1", resolve); });
issuer = `http://127.0.0.1:${idpServer.address().port}`;

// ── App under test ───────────────────────────────────────────────────────────

const tmp = mkdtempSync(path.join(tmpdir(), "anylist-oidc-test-"));
Object.assign(process.env, {
  DATA_DIR: tmp,
  SERVER_SECRET_KEY: randomBytes(32).toString("hex"),
  OIDC_ISSUER: issuer,
  OIDC_CLIENT_ID: CLIENT_ID,
  OIDC_CLIENT_SECRET: CLIENT_SECRET,
  OIDC_REQUIRED_GROUP: "anylist",
});

const db = await import("../src/http/db.js");
const { default: oauthRouter } = await import("../src/http/auth/oauth.js");
const { default: onboardingRouter } = await import("../src/http/onboarding.js");
const { renderTemplate } = await import("../src/http/template.js");

const viewsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "http", "views");
let appServer;
let base;

before(async () => {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(session({ secret: "test", resave: false, saveUninitialized: false, cookie: { sameSite: "lax" } }));
  app.set("views", viewsDir);
  app.set("view engine", "html");
  app.engine("html", renderTemplate);
  app.use(oauthRouter);
  app.use(onboardingRouter);
  await new Promise(resolve => { appServer = app.listen(0, "127.0.0.1", resolve); });
  base = `http://127.0.0.1:${appServer.address().port}`;
  process.env.BASE_URL = base;
});

after(() => {
  appServer.close();
  idpServer.close();
  rmSync(tmp, { recursive: true, force: true });
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function browser() {
  let cookie = "";
  // Cookie jar for the app only; the IdP is stateless here.
  return async function request(url) {
    const full = url.startsWith("http") ? url : base + url;
    const isApp = full.startsWith(base);
    const res = await fetch(full, { redirect: "manual", headers: isApp && cookie ? { cookie } : {} });
    const setCookie = res.headers.get("set-cookie");
    if (isApp && setCookie) cookie = setCookie.split(";")[0];
    return res;
  };
}

/** Runs /auth/oidc/login → IdP → callback; returns the callback response. */
async function signIn(request, identity) {
  nextIdentity = identity;
  const start = await request("/auth/oidc/login");
  assert.equal(start.status, 302);
  const toIdp = start.headers.get("location");
  assert.ok(toIdp.startsWith(`${issuer}/authorize`));
  const back = await request(toIdp);
  return request(back.headers.get("location"));
}

const identity = (sub, email, groups = ["anylist"]) => ({ sub, email, "cognito:groups": groups });

// ── Tests ────────────────────────────────────────────────────────────────────

describe("single sign-on", () => {
  it("creates a user on first sign-in and sends them to setup", async () => {
    const res = await signIn(browser(), identity("sub-new", "new@example.com"));
    assert.equal(res.headers.get("location"), "/setup");
    assert.equal(db.getUserByOidcSub("sub-new").email, "new@example.com");
    assert.ok(db.isUserAllowed(db.getUserByOidcSub("sub-new").id));
  });

  it("rejects identities without the required group", async () => {
    const res = await signIn(browser(), identity("sub-nogroup", "nogroup@example.com", ["other"]));
    assert.equal(res.status, 403);
    assert.match(await res.text(), /not authorized/);
    assert.equal(db.getUserByOidcSub("sub-nogroup"), undefined);
  });

  it("rejects a callback whose state does not match", async () => {
    const request = browser();
    nextIdentity = identity("sub-state", "state@example.com");
    const start = await request("/auth/oidc/login");
    const back = new URL((await request(start.headers.get("location"))).headers.get("location"));
    back.searchParams.set("state", "forged");
    const res = await request(back.href);
    assert.equal(res.status, 403);
    assert.equal(db.getUserByOidcSub("sub-state"), undefined);
  });

  it("links a pre-existing password account, keeping its AnyList login but dropping password and tokens", async () => {
    const user = db.createUser({ id: "legacy-user", email: "legacy@example.com", pwHash: "$2b$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" });
    db.upsertAnyListCredentials(user.id, { username: "legacy@example.com", password: "anylist-pw", defaultListName: null });
    db.saveOAuthTokens({ accessToken: "old-at", refreshToken: "old-rt", userId: user.id, clientId: "c", scope: "mcp" });

    // Start from a pending MCP authorization so the flow ends at the consent page.
    const { client_id } = await (await fetch(`${base}/oauth/register`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://claude.ai/api/mcp/auth_callback"] }),
    })).json();
    const request = browser();
    await request(`/oauth/authorize?${new URLSearchParams({ client_id, redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_challenge: "c", code_challenge_method: "S256" })}`);
    const res = await signIn(request, identity("sub-legacy", "legacy@example.com"));

    assert.equal(res.headers.get("location"), "/oauth/consent");
    const linked = db.getUserById(user.id);
    assert.equal(linked.oidc_sub, "sub-legacy");
    assert.equal(linked.pw_hash, null);
    assert.equal(db.getTokenRecord("old-at"), undefined);
    assert.equal(db.getAnyListCredentials(user.id).password, "anylist-pw");
  });

  it("treats users not signed in through single sign-on as not allowed", () => {
    const user = db.createUser({ id: "unlinked", email: "unlinked@example.com" });
    assert.equal(db.isUserAllowed(user.id), false);
  });

  it("turns off password registration, password login and Google sign-in", async () => {
    for (const p of ["/auth/register", "/auth/login", "/auth/google"]) {
      const res = await fetch(base + p, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "email=a@example.com&password=x" });
      assert.equal(res.status, 404, p);
    }
  });
});
